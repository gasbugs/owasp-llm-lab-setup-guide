"""Persistent P04 execution/call records; no provider call or course verdict."""
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import time
from uuid import UUID, uuid4

from p04_contract import ACTIVITY_ID, CONTRACT_VERSION, PRACTICE_ID, canonical, expected_arguments


class LedgerError(RuntimeError):
    def __init__(self, status):
        super().__init__("P04 execution state is unavailable or incompatible")
        self.status = status


def identifier(value):
    try:
        if str(UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise LedgerError(422) from None


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise LedgerError(422)


class GuardrailLedger:
    def __init__(self, path, *, now=time.time):
        self.path, self.now = str(path), now
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS p04_executions (
                execution_id TEXT PRIMARY KEY, suite_id TEXT NOT NULL,
                source_digest TEXT NOT NULL, runner_digest TEXT NOT NULL,
                resource_digest TEXT NOT NULL, provider_mode TEXT NOT NULL,
                body_json TEXT NOT NULL, guardrail_json TEXT NOT NULL,
                capability_hash TEXT NOT NULL UNIQUE, started_at REAL NOT NULL, closed_at REAL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS p04_calls (
                execution_id TEXT PRIMARY KEY, operation TEXT NOT NULL,
                request_json TEXT NOT NULL, request_digest TEXT NOT NULL,
                state TEXT NOT NULL, started_at REAL NOT NULL,
                dispatched_at REAL, finished_at REAL, response_json TEXT,
                observation_id TEXT UNIQUE, provider_request_id TEXT UNIQUE)""")
            db.execute("CREATE TABLE IF NOT EXISTS p04_policy_audits (execution_id TEXT NOT NULL, "
                       "phase TEXT NOT NULL, receipt_json TEXT NOT NULL, PRIMARY KEY(execution_id,phase))")
            db.execute("CREATE TABLE IF NOT EXISTS p04_policy_audit_requests "
                       "(request_id TEXT PRIMARY KEY, execution_id TEXT NOT NULL, phase TEXT NOT NULL)")

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def stamp(self):
        stamp = self.now()
        if type(stamp) not in (int, float) or not math.isfinite(stamp) or stamp <= 0:
            raise LedgerError(409)
        return stamp

    def register(self, suite_id, execution_id, source_digest, runner_digest,
                 resource_digest, provider_mode, body, guardrail):
        identifier(suite_id)
        identifier(execution_id)
        for value in (source_digest, runner_digest, resource_digest):
            digest(value)
        if provider_mode not in ("aws", "contract"):
            raise LedgerError(422)
        try:
            expected_arguments({"operation": "apply_guardrail", "text": "reference"}, guardrail)
            encoded_body, encoded_guardrail = canonical(body).decode(), canonical(guardrail).decode()
            if len(encoded_body.encode()) > 16384:
                raise ValueError()
        except (ValueError, TypeError):
            raise LedgerError(422) from None
        token, stamp = secrets.token_urlsafe(48), self.stamp()
        try:
            with self.connect() as db:
                db.execute("INSERT INTO p04_executions VALUES(?,?,?,?,?,?,?,?,?,?,NULL)",
                           (execution_id, suite_id, source_digest, runner_digest, resource_digest,
                            provider_mode, encoded_body, encoded_guardrail,
                            hashlib.sha256(token.encode()).hexdigest(), stamp))
        except sqlite3.IntegrityError:
            raise LedgerError(409) from None
        return {"practice_id": PRACTICE_ID, "activity_id": ACTIVITY_ID,
                "contract_version": CONTRACT_VERSION, "suite_id": suite_id,
                "execution_id": execution_id, "started_at": stamp, "capability": token}

    def _execution(self, db, execution_id):
        row = db.execute("SELECT * FROM p04_executions WHERE execution_id=?", (execution_id,)).fetchone()
        if row is None:
            raise LedgerError(404)
        return row

    def _pending(self, db, execution_id):
        execution = self._execution(db, execution_id)
        call = db.execute("SELECT * FROM p04_calls WHERE execution_id=?", (execution_id,)).fetchone()
        stamp = self.stamp()
        if (execution["closed_at"] is not None or call is None or call["state"] != "pending"
                or not 0 <= stamp - execution["started_at"] < 180 or stamp < call["started_at"]):
            raise LedgerError(409)
        return call, stamp

    def authorize(self, token, suite_id, execution_id):
        """Read-only check before resolving any provider; reserve checks again atomically."""
        if not isinstance(token, str) or not token.isascii() or not 40 <= len(token) <= 256:
            raise LedgerError(401)
        with self.connect() as db:
            try:
                row = self._execution(db, execution_id)
            except LedgerError:
                raise LedgerError(401) from None
            if not hmac.compare_digest(row["capability_hash"], hashlib.sha256(token.encode()).hexdigest()):
                raise LedgerError(401)
            if row["suite_id"] != suite_id:
                raise LedgerError(403)
            if row["closed_at"] is not None or not 0 <= self.stamp() - row["started_at"] < 180:
                raise LedgerError(409)

    def reserve(self, token, suite_id, execution_id, operation, payload):
        if operation not in ("apply_guardrail", "converse"):
            raise LedgerError(422)
        if not isinstance(token, str) or not token.isascii() or not 40 <= len(token) <= 256:
            raise LedgerError(401)
        try:
            raw = canonical(payload)
            if not isinstance(payload, dict) or len(raw) > 32768:
                raise ValueError()
        except (ValueError, TypeError):
            raise LedgerError(422) from None
        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row = self._execution(db, execution_id)
                if not hmac.compare_digest(row["capability_hash"], hashlib.sha256(token.encode()).hexdigest()):
                    raise LedgerError(401)
                if row["suite_id"] != suite_id:
                    raise LedgerError(403)
                stamp = self.stamp()
                if row["closed_at"] is not None or not 0 <= stamp - row["started_at"] < 180:
                    raise LedgerError(409)
                db.execute("INSERT INTO p04_calls VALUES(?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL)",
                           (execution_id, operation, raw.decode(), hashlib.sha256(raw).hexdigest(), "pending", stamp))
        except sqlite3.IntegrityError:
            raise LedgerError(409) from None

    def dispatch(self, execution_id):
        """Trusted adapter only: mark a validated call immediately before dispatch."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            call, stamp = self._pending(db, execution_id)
            if call["dispatched_at"] is not None:
                raise LedgerError(409)
            db.execute("UPDATE p04_calls SET dispatched_at=? WHERE execution_id=?", (stamp, execution_id))

    def policy_audit(self, execution_id, phase, receipt):
        if phase not in ('before', 'after') or not isinstance(receipt, dict):
            raise LedgerError(409)
        try:
            raw = canonical(receipt).decode()
            ids = receipt['aws_request_ids']
            started, observed = receipt['started_at'], receipt['observed_at']
            if (len(raw.encode()) > 16384 or receipt['scope'] != 'aws-policy-audit'
                    or type(started) not in (int, float) or type(observed) not in (int, float)
                    or not math.isfinite(started) or not math.isfinite(observed)
                    or not 0 < started <= observed or observed - started >= 12
                    or not isinstance(ids, list) or len(ids) != 3
                    or any(not isinstance(value, str) or not value.isascii() or not 1 <= len(value) <= 256 for value in ids)
                    or len(set(ids)) != 3):
                raise LedgerError(409)
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                call, stamp = self._pending(db, execution_id)
                execution = self._execution(db, execution_id)
                before = db.execute("SELECT 1 FROM p04_policy_audits WHERE execution_id=? AND phase='before'",
                                    (execution_id,)).fetchone()
                if (execution['provider_mode'] != 'aws'
                        or hashlib.sha256(canonical(receipt['resources'])).hexdigest() != execution['resource_digest']
                        or not call['started_at'] <= started <= observed <= stamp
                        or phase == 'before' and call['dispatched_at'] is not None
                        or phase == 'after' and (call['dispatched_at'] is None or before is None
                                                or started < call['dispatched_at'])):
                    raise LedgerError(409)
                db.execute('INSERT INTO p04_policy_audits VALUES(?,?,?)', (execution_id, phase, raw))
                for value in ids:
                    db.execute('INSERT INTO p04_policy_audit_requests VALUES(?,?,?)', (value, execution_id, phase))
        except (ValueError, KeyError, TypeError, sqlite3.IntegrityError):
            raise LedgerError(409) from None

    def finish(self, execution_id, response=None):
        """Trusted adapter only: preserve errors without asserting provider non-execution."""
        raw = None
        if response is not None:
            try:
                raw = canonical(response).decode()
                if not isinstance(response, dict) or len(raw.encode()) > 32768:
                    raise ValueError()
            except (ValueError, TypeError):
                raise LedgerError(502) from None
        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                call, stamp = self._pending(db, execution_id)
                execution = self._execution(db, execution_id)
                provider_id = None
                if call["dispatched_at"] is not None and stamp < call["dispatched_at"]:
                    raise LedgerError(409)
                if response is not None:
                    if call["dispatched_at"] is None or stamp < call["dispatched_at"]:
                        raise LedgerError(409)
                    if execution["provider_mode"] == "aws":
                        metadata = response.get("ResponseMetadata")
                        provider_id = metadata.get("RequestId") if isinstance(metadata, dict) else None
                        if not isinstance(provider_id, str) or not 1 <= len(provider_id) <= 256:
                            raise LedgerError(502)
                db.execute("UPDATE p04_calls SET state=?,finished_at=?,response_json=?,observation_id=?,"
                           "provider_request_id=? WHERE execution_id=?",
                           ("complete" if response is not None else "error", stamp, raw,
                            str(uuid4()), provider_id, execution_id))
        except sqlite3.IntegrityError:
            raise LedgerError(409) from None

    def close(self, execution_id):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._execution(db, execution_id)
            if row["closed_at"] is not None:
                return {"execution_id": execution_id, "closed_at": row["closed_at"]}
            call = db.execute("SELECT * FROM p04_calls WHERE execution_id=?", (execution_id,)).fetchone()
            stamp = self.stamp()
            if (stamp < row["started_at"]
                    or call is not None and (call["state"] == "pending" or stamp < call["finished_at"])):
                raise LedgerError(409)
            db.execute("UPDATE p04_executions SET closed_at=? WHERE execution_id=?", (stamp, execution_id))
        return {"execution_id": execution_id, "closed_at": stamp}

    def read(self, execution_id):
        with self.connect() as db:
            db.execute("BEGIN")
            row = dict(self._execution(db, execution_id))
            calls = [dict(call) for call in db.execute("SELECT * FROM p04_calls WHERE execution_id=?", (execution_id,))]
            audits = {audit['phase']: json.loads(audit['receipt_json']) for audit in db.execute(
                'SELECT phase,receipt_json FROM p04_policy_audits WHERE execution_id=?', (execution_id,))}
        row.pop("capability_hash")
        row["body"], row["guardrail"] = json.loads(row.pop("body_json")), json.loads(row.pop("guardrail_json"))
        for call in calls:
            call["request"] = json.loads(call.pop("request_json"))
            raw = call.pop("response_json")
            call["response"] = json.loads(raw) if raw is not None else None
        return {**row, "practice_id": PRACTICE_ID, "activity_id": ACTIVITY_ID,
                "contract_version": CONTRACT_VERSION, "closed": row["closed_at"] is not None,
                "calls": calls, "policy_audits": audits}
