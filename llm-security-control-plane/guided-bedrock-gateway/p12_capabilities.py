"""P12-only one-use grants; persistent metadata, never raw tokens or model text."""
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import time
from uuid import UUID

MODEL_ID = "us.amazon.nova-lite-v1:0"
ROLES = ("input_rail", "retrieval_rail", "output_rail", "main")
MARKERS = {role: f"{MODEL_ID}#p12-{role}" for role in ROLES}


class GrantError(ValueError):
    def __init__(self, status, reason):
        self.status = status
        super().__init__(reason)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class CapabilityStore:
    def __init__(self, path, *, now=time.time):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.now = now
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS p12_suites (
                    suite_id TEXT PRIMARY KEY, created REAL NOT NULL, closed REAL);
                CREATE TABLE IF NOT EXISTS p12_grants (
                    token_digest TEXT PRIMARY KEY, suite_id TEXT NOT NULL,
                    execution_id TEXT NOT NULL, role TEXT NOT NULL, model TEXT NOT NULL,
                    issued REAL NOT NULL, expires REAL NOT NULL, state TEXT NOT NULL,
                    reserved REAL, finished REAL, request_digest TEXT, evidence TEXT,
                    UNIQUE(suite_id, execution_id, role));
                CREATE TABLE IF NOT EXISTS p12_provider_ids (
                    provider_request_id TEXT PRIMARY KEY, token_digest TEXT UNIQUE NOT NULL);
            """)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def issue(self, suite_id, execution_ids):
        try:
            suite_id = str(UUID(suite_id))
            ids = [str(UUID(value)) for value in execution_ids]
        except (ValueError, TypeError, AttributeError):
            raise GrantError(422, "invalid execution identifiers") from None
        if not 1 <= len(ids) <= 32 or len(set(ids)) != len(ids):
            raise GrantError(422, "unique execution identifiers required")
        created = self.now()
        grants = []
        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO p12_suites VALUES(?,?,NULL)", (suite_id, created))
                for execution in ids:
                    for role in ROLES:
                        token = secrets.token_urlsafe(48)
                        db.execute("INSERT INTO p12_grants VALUES(?,?,?,?,?,?,?,'issued',NULL,NULL,NULL,NULL)",
                                   (digest(token), suite_id, execution, role, MARKERS[role], created, created + 180))
                        grants.append({"suite_id": suite_id, "execution_id": execution,
                                       "role": role, "model": MARKERS[role], "capability": token,
                                       "expires_at": created + 180})
        except sqlite3.IntegrityError:
            raise GrantError(409, "suite already exists") from None
        return {"suite_id": suite_id, "created_at": created, "grants": grants}

    def reserve(self, token, *, suite_id, execution_id, role, model, request_digest):
        if (not isinstance(token, str) or not 40 <= len(token) <= 256
                or not isinstance(request_digest, str) or len(request_digest) != 64
                or any(char not in "0123456789abcdef" for char in request_digest)):
            raise GrantError(401, "invalid capability or request binding")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT g.*,s.closed FROM p12_grants g JOIN p12_suites s USING(suite_id) "
                             "WHERE token_digest=?", (digest(token),)).fetchone()
            if not row:
                raise GrantError(401, "unknown capability")
            if (row["suite_id"], row["execution_id"], row["role"], row["model"]) != (suite_id, execution_id, role, model):
                raise GrantError(403, "capability scope mismatch")
            if row["closed"] is not None or row["state"] != "issued":
                raise GrantError(409, "capability already consumed or suite closed")
            current = self.now()
            if not row["issued"] <= current < row["expires"]:
                raise GrantError(403, "capability expired or clock invalid")
            db.execute("UPDATE p12_grants SET state='reserved',reserved=?,request_digest=? WHERE token_digest=?",
                       (current, request_digest, digest(token)))
        return {"suite_id": suite_id, "execution_id": execution_id, "role": role, "model": model,
                "token_digest": digest(token), "request_digest": request_digest}

    def complete(self, token, provider):
        # Provider is produced by the trusted SDK adapter, never a Browser request.
        request_id, text, usage = (provider.get(key) for key in ("provider_request_id", "text", "usage"))
        if (not isinstance(request_id, str) or not request_id or len(request_id) > 256
                or not isinstance(text, str) or not text or len(text) > 32000
                or not isinstance(usage, dict)
                or any(type(usage.get(key)) is not int or usage[key] < 0
                       for key in ("inputTokens", "outputTokens", "totalTokens"))
                or usage["totalTokens"] != usage["inputTokens"] + usage["outputTokens"]
                or provider.get("stop_reason") not in {"end_turn", "max_tokens", "stop_sequence"}):
            raise GrantError(502, "incomplete provider evidence")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM p12_grants WHERE token_digest=?", (digest(token),)).fetchone()
            if not row or row["state"] != "reserved":
                raise GrantError(409, "capability is not reserved")
            evidence = {"provider_request_id": request_id, "actual_model_id": MODEL_ID,
                        "response_digest": digest(text), "response_bytes": len(text.encode()),
                        "usage": {key: usage[key] for key in ("inputTokens", "outputTokens", "totalTokens")},
                        "stop_reason": provider["stop_reason"]}
            if row["role"] != "main":
                evidence["classifier_schema_valid"] = text in {"Yes", "No"}
                evidence["classifier_answer"] = text if text in {"Yes", "No"} else None
            else:
                binding = provider.get("main_input")
                if binding is not None:
                    if not isinstance(binding, dict) or type(binding.get("schema_valid")) is not bool:
                        raise GrantError(502, "invalid Main input evidence")
                    keys = {"schema_valid", "prompt_digest"}
                    if binding["schema_valid"]:
                        keys |= {"question_digest", "context_digest", "question_bytes", "context_bytes"}
                    if set(binding) != keys:
                        raise GrantError(502, "invalid Main input fields")
                    for key, value in binding.items():
                        if key.endswith("_digest") and (not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value)):
                            raise GrantError(502, "invalid Main input digest")
                        if key.endswith("_bytes") and (type(value) is not int or not 1 <= value <= 64000):
                            raise GrantError(502, "invalid Main input size")
                evidence["main_input"] = binding
            try:
                db.execute("INSERT INTO p12_provider_ids VALUES(?,?)", (request_id, digest(token)))
            except sqlite3.IntegrityError:
                raise GrantError(409, "provider identity already recorded") from None
            db.execute("UPDATE p12_grants SET state='completed',finished=?,evidence=? WHERE token_digest=?",
                       (self.now(), json.dumps(evidence), digest(token)))
        return evidence

    def fail(self, token):
        with self.connect() as db:
            changed = db.execute("UPDATE p12_grants SET state='error',finished=? "
                                 "WHERE token_digest=? AND state='reserved'", (self.now(), digest(token))).rowcount
            if changed != 1:
                raise GrantError(409, "capability is not reserved")

    def close(self, suite_id):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            suite = db.execute("SELECT * FROM p12_suites WHERE suite_id=?", (suite_id,)).fetchone()
            if not suite:
                raise GrantError(404, "suite not found")
            if db.execute("SELECT 1 FROM p12_grants WHERE suite_id=? AND state='reserved'", (suite_id,)).fetchone():
                raise GrantError(409, "provider calls remain unresolved")
            closed = suite["closed"] if suite["closed"] is not None else self.now()
            db.execute("UPDATE p12_suites SET closed=? WHERE suite_id=?", (closed, suite_id))
            db.execute("UPDATE p12_grants SET state='closed_unused' WHERE suite_id=? AND state='issued'", (suite_id,))
        return {"suite_id": suite_id, "closed_at": closed}

    def ledger(self, suite_id):
        with self.connect() as db:
            suite = db.execute("SELECT * FROM p12_suites WHERE suite_id=?", (suite_id,)).fetchone()
            grants = db.execute("SELECT * FROM p12_grants WHERE suite_id=? ORDER BY execution_id,role", (suite_id,)).fetchall()
        if not suite:
            raise GrantError(404, "suite not found")
        return {"practice_id": "P12", "contract_version": 2, **dict(suite),
                "grants": [{**dict(row), "evidence": json.loads(row["evidence"]) if row["evidence"] else None}
                           for row in grants]}
