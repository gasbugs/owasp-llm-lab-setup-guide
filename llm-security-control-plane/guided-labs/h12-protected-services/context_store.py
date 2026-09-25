"""P12 synthetic identities and real lexical retrieval; not OAuth, embeddings or AWS."""
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time
from uuid import UUID


class ContextError(ValueError):
    def __init__(self, status, message, evidence=None):
        self.status = status
        self.evidence = evidence
        super().__init__(message)


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", value):
        raise ContextError(422, "invalid identifier")
    return value


def bounded(value, maximum):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ContextError(422, "invalid text")
    return value


class ContextStore:
    def __init__(self, path, source_digest, *, now=time.time):
        if not re.fullmatch(r"[0-9a-f]{64}", source_digest):
            raise ValueError("source digest required")
        self.path, self.source_digest, self.now = Path(path), source_digest, now
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS suites (
                    suite_id TEXT PRIMARY KEY, created REAL NOT NULL, closed REAL, source_digest TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS executions (
                    suite_id TEXT, execution_id TEXT, subject TEXT, tenant TEXT, authorized INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(suite_id, execution_id));
                CREATE TABLE IF NOT EXISTS identities (
                    suite_id TEXT, token_digest TEXT, subject TEXT, tenant TEXT, can_read INTEGER NOT NULL,
                    PRIMARY KEY(suite_id, token_digest));
                CREATE VIRTUAL TABLE IF NOT EXISTS documents USING fts5(suite_id UNINDEXED, document_id UNINDEXED, tenant UNINDEXED, text);
                CREATE TABLE IF NOT EXISTS calls (
                    suite_id TEXT, execution_id TEXT, stage TEXT, started REAL NOT NULL, finished REAL,
                    state TEXT NOT NULL, input_digest TEXT NOT NULL, evidence TEXT,
                    PRIMARY KEY(suite_id, execution_id, stage));
            """)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def register(self, suite_id, execution_ids, documents):
        suite_id = str(UUID(suite_id))
        execution_ids = [str(UUID(value)) for value in execution_ids]
        if not 1 <= len(execution_ids) <= 32 or len(set(execution_ids)) != len(execution_ids):
            raise ContextError(422, "invalid executions")
        if not isinstance(documents, list) or not 1 <= len(documents) <= 8:
            raise ContextError(422, "bounded corpus required")
        seen = set()
        for doc in documents:
            if not isinstance(doc, dict) or set(doc) != {"document_id", "tenant", "text"}:
                raise ContextError(422, "invalid document")
            identifier(doc["document_id"])
            identifier(doc["tenant"])
            bounded(doc["text"], 4000)
            if doc["document_id"] in seen:
                raise ContextError(422, "duplicate document")
            seen.add(doc["document_id"])
        credentials = {role: secrets.token_urlsafe(48) for role in ("reader", "visitor")}
        created = self.now()
        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO suites VALUES(?,?,NULL,?)", (suite_id, created, self.source_digest))
                db.executemany("INSERT INTO executions(suite_id,execution_id) VALUES(?,?)", [(suite_id, value) for value in execution_ids])
                db.executemany("INSERT INTO identities VALUES(?,?,?,?,?)",
                    [(suite_id, digest(token), role, "team-a", int(role == "reader")) for role, token in credentials.items()])
                db.executemany("INSERT INTO documents VALUES(?,?,?,?)",
                    [(suite_id, doc["document_id"], doc["tenant"], doc["text"]) for doc in documents])
        except sqlite3.IntegrityError:
            raise ContextError(409, "suite already registered") from None
        return {"suite_id": suite_id, "created_at": created, "expires_at": created + 180,
                "credentials": credentials, "tenant": "team-a", "service_digest": self.source_digest}

    def execute(self, suite_id, execution_id, stage, value):
        suite_id, execution_id = str(UUID(suite_id)), str(UUID(execution_id))
        if stage not in {"authenticate", "authorize", "retrieval"}:
            raise ContextError(422, "unknown context stage")
        bounded(value, 256 if stage == "authenticate" else 16000)
        if stage == "authorize":
            identifier(value)
        key = suite_id, execution_id, stage
        error = None
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            suite = db.execute("SELECT * FROM suites WHERE suite_id=?", (suite_id,)).fetchone()
            execution = db.execute("SELECT * FROM executions WHERE suite_id=? AND execution_id=?", key[:2]).fetchone()
            if not suite or not execution:
                raise ContextError(404, "registered execution not found")
            if suite["closed"] is not None or not 0 <= self.now() - suite["created"] < 180:
                raise ContextError(409, "suite closed or expired")
            if suite["source_digest"] != self.source_digest:
                raise ContextError(409, "suite execution build mismatch")
            try:
                db.execute("INSERT INTO calls VALUES(?,?,?,?,NULL,'pending',?,NULL)", (*key, self.now(), digest(value)))
            except sqlite3.IntegrityError:
                raise ContextError(409, "stage already attempted") from None
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            execution = db.execute("SELECT * FROM executions WHERE suite_id=? AND execution_id=?", key[:2]).fetchone()
            try:
                result = self._perform(db, execution, stage, value)
                evidence = {**result.pop("evidence"), "stage": stage, "input_digest": digest(value),
                            "service_digest": self.source_digest, "backend": "synthetic-sqlite-fts"}
                db.execute("UPDATE calls SET finished=?,state='completed',evidence=? WHERE suite_id=? AND execution_id=? AND stage=?",
                           (self.now(), json.dumps(evidence), *key))
            except Exception as exc:
                error = exc if isinstance(exc, ContextError) else ContextError(503, "context processing failed")
                db.execute("UPDATE calls SET finished=?,state=?,evidence=? WHERE suite_id=? AND execution_id=? AND stage=?",
                           (self.now(), "rejected" if error.evidence else "error",
                            json.dumps(error.evidence) if error.evidence else None, *key))
        if error:
            raise error from None
        return {"suite_id": suite_id, "execution_id": execution_id, **result, "evidence": evidence}

    def _perform(self, db, execution, stage, value):
        key = execution["suite_id"], execution["execution_id"]
        if stage == "authenticate":
            identity = db.execute("SELECT * FROM identities WHERE suite_id=? AND token_digest=?", (key[0], digest(value))).fetchone()
            if identity:
                db.execute("UPDATE executions SET subject=?,tenant=? WHERE suite_id=? AND execution_id=?",
                           (identity["subject"], identity["tenant"], *key))
            return {"allowed": identity is not None,
                    "evidence": {"authenticated": identity is not None, "subject": identity["subject"] if identity else None}}
        if stage == "authorize":
            identity = db.execute("SELECT * FROM identities WHERE suite_id=? AND subject=?", (key[0], execution["subject"])).fetchone()
            allowed = bool(identity and identity["can_read"] and identity["tenant"] == value)
            db.execute("UPDATE executions SET authorized=? WHERE suite_id=? AND execution_id=?", (int(allowed), *key))
            return {"allowed": allowed, "evidence": {"authorized": allowed, "subject": execution["subject"],
                                                       "requested_tenant": value, "required_scope": "knowledge:read"}}
        if not execution["authorized"]:
            raise ContextError(403, "retrieval requires authorization", {"query_executed": False, "authorization_denied": True})
        terms = list(dict.fromkeys(re.findall(r"\w+", value, flags=re.UNICODE)))[:16]
        query = " OR ".join('"' + term + '"' for term in terms)
        rows = db.execute("SELECT document_id,tenant,text FROM documents WHERE documents MATCH ? AND suite_id=? AND tenant=? ORDER BY rank,document_id LIMIT 3",
                          (query, key[0], execution["tenant"])).fetchall() if terms else []
        text = "\n\n".join(row["text"] for row in rows)
        return {"text": text, "evidence": {"query_executed": bool(terms), "authorized_tenant": execution["tenant"],
                "hits": [{"document_id": row["document_id"], "tenant": row["tenant"], "text_digest": digest(row["text"])} for row in rows],
                "output_digest": digest(text), "output_bytes": len(text.encode())}}

    def close(self, suite_id):
        suite_id = str(UUID(suite_id))
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            suite = db.execute("SELECT * FROM suites WHERE suite_id=?", (suite_id,)).fetchone()
            if not suite:
                raise ContextError(404, "suite not found")
            if db.execute("SELECT 1 FROM calls WHERE suite_id=? AND state='pending'", (suite_id,)).fetchone():
                raise ContextError(409, "context processing pending")
            closed = suite["closed"] if suite["closed"] is not None else self.now()
            db.execute("UPDATE suites SET closed=? WHERE suite_id=?", (closed, suite_id))
        return {"suite_id": suite_id, "closed_at": closed}

    def ledger(self, suite_id):
        suite_id = str(UUID(suite_id))
        with self.connect() as db:
            suite = db.execute("SELECT * FROM suites WHERE suite_id=?", (suite_id,)).fetchone()
            if not suite:
                raise ContextError(404, "suite not found")
            executions = db.execute("SELECT execution_id FROM executions WHERE suite_id=? ORDER BY execution_id", (suite_id,)).fetchall()
            calls = db.execute("SELECT * FROM calls WHERE suite_id=? ORDER BY started,execution_id,stage", (suite_id,)).fetchall()
        entries = [{**dict(row), "evidence": json.loads(row["evidence"]) if row["evidence"] else None} for row in calls]
        retrieval = [row for row in entries if row["stage"] == "retrieval"]
        count = None
        if suite["closed"] is not None and all(row["evidence"] and type(row["evidence"].get("query_executed")) is bool for row in retrieval):
            count = sum(row["evidence"]["query_executed"] for row in retrieval)
        return {"practice_id": "P12", "contract_version": 2, "component": "p12-context", "suite_id": suite_id,
                "created_at": suite["created"], "closed_at": suite["closed"], "service_digest": suite["source_digest"],
                "execution_ids": [row["execution_id"] for row in executions],
                "retrieval_count": count, "calls": entries}
