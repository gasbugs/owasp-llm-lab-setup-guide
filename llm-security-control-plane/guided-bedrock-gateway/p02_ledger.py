"""P02 persistent call lifecycle. This module makes no course verdict or AWS call."""
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import time
from uuid import UUID

CONTRACT = "p02-document-v1"
OPERATIONS = {"store_source", "embed"}


class LedgerError(RuntimeError):
    def __init__(self, status):
        super().__init__("P02 execution state is unavailable or incompatible")
        self.status = status


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise LedgerError(422)
    return value


def identifier(value):
    try:
        if str(UUID(value)) != value:
            raise ValueError()
        return value
    except (ValueError, TypeError, AttributeError):
        raise LedgerError(422) from None


class DocumentLedger:
    def __init__(self, path, *, now=time.time):
        self.path, self.now = str(path), now
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS p02_executions (
                execution_id TEXT PRIMARY KEY, suite_id TEXT NOT NULL,
                source_digest TEXT NOT NULL, runner_digest TEXT NOT NULL,
                capability_hash TEXT NOT NULL UNIQUE, started_at REAL NOT NULL,
                closed_at REAL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS p02_calls (
                execution_id TEXT NOT NULL, operation TEXT NOT NULL,
                sequence INTEGER NOT NULL, request_digest TEXT NOT NULL,
                state TEXT NOT NULL, started_at REAL NOT NULL, finished_at REAL,
                response_json TEXT, provider_request_id TEXT UNIQUE,
                PRIMARY KEY(execution_id, operation))""")

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def stamp(self):
        stamp = self.now()
        if type(stamp) not in (int, float) or not math.isfinite(stamp) or stamp <= 0:
            raise LedgerError(409)
        return stamp

    def register(self, suite_id, execution_id, source_digest, runner_digest):
        identifier(suite_id)
        identifier(execution_id)
        digest(source_digest)
        digest(runner_digest)
        token, stamp = secrets.token_urlsafe(48), self.stamp()
        try:
            with self.connect() as db:
                db.execute("INSERT INTO p02_executions VALUES(?,?,?,?,?,?,NULL)",
                           (execution_id, suite_id, source_digest, runner_digest,
                            hashlib.sha256(token.encode()).hexdigest(), stamp))
        except sqlite3.IntegrityError:
            raise LedgerError(409) from None
        return {"practice_id": "P02", "activity_id": "H02", "contract_version": CONTRACT,
                "suite_id": suite_id, "execution_id": execution_id,
                "started_at": stamp, "capability": token}

    def _execution(self, db, execution_id):
        row = db.execute("SELECT * FROM p02_executions WHERE execution_id=?", (execution_id,)).fetchone()
        if row is None:
            raise LedgerError(404)
        return row

    def reserve(self, token, suite_id, execution_id, operation, request_digest):
        if operation not in OPERATIONS:
            raise LedgerError(422)
        digest(request_digest)
        if not isinstance(token, str) or not token.isascii() or not 40 <= len(token) <= 256:
            raise LedgerError(401)
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
            calls = db.execute("SELECT operation, state FROM p02_calls WHERE execution_id=?", (execution_id,)).fetchall()
            if any(call["state"] != "complete" or call["operation"] == operation for call in calls):
                raise LedgerError(409)
            db.execute("INSERT INTO p02_calls VALUES(?,?,?,?,?,?,NULL,NULL,NULL)",
                       (execution_id, operation, len(calls) + 1, request_digest, "pending", stamp))
        return {"execution_id": execution_id, "operation": operation, "sequence": len(calls) + 1}

    def finish(self, execution_id, operation, response=None):
        """Called only by the trusted provider adapter, never the learner HTTP body."""
        serialized, provider_id = None, None
        if response is not None:
            if not isinstance(response, dict):
                raise LedgerError(502)
            provider_id = response.get("provider_request_id")
            if not isinstance(provider_id, str) or not provider_id or len(provider_id) > 256:
                raise LedgerError(502)
            try:
                serialized = json.dumps(response, allow_nan=False, ensure_ascii=False)
            except (ValueError, TypeError):
                raise LedgerError(502) from None
            if len(serialized.encode()) > 16384:
                raise LedgerError(502)
        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row = self._execution(db, execution_id)
                call = db.execute("SELECT * FROM p02_calls WHERE execution_id=? AND operation=?",
                                  (execution_id, operation)).fetchone()
                stamp = self.stamp()
                if row["closed_at"] is not None or call is None or call["state"] != "pending" or stamp < call["started_at"]:
                    raise LedgerError(409)
                db.execute("UPDATE p02_calls SET state=?,finished_at=?,response_json=?,provider_request_id=? "
                           "WHERE execution_id=? AND operation=?",
                           ("complete" if response is not None else "error", stamp, serialized, provider_id,
                            execution_id, operation))
        except sqlite3.IntegrityError:
            raise LedgerError(409) from None

    def close(self, execution_id):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._execution(db, execution_id)
            if row["closed_at"] is not None:
                return {"execution_id": execution_id, "closed_at": row["closed_at"]}
            calls = db.execute("SELECT * FROM p02_calls WHERE execution_id=?", (execution_id,)).fetchall()
            stamp = self.stamp()
            if stamp < row["started_at"] or any(call["state"] == "pending" or stamp < call["finished_at"] for call in calls):
                raise LedgerError(409)
            db.execute("UPDATE p02_executions SET closed_at=? WHERE execution_id=?", (stamp, execution_id))
        return {"execution_id": execution_id, "closed_at": stamp}

    def read(self, execution_id):
        with self.connect() as db:
            db.execute("BEGIN")
            row = dict(self._execution(db, execution_id))
            calls = [dict(call) for call in db.execute(
                "SELECT * FROM p02_calls WHERE execution_id=? ORDER BY sequence", (execution_id,))]
        row.pop("capability_hash")
        for call in calls:
            raw = call.pop("response_json")
            call["response"] = json.loads(raw) if raw is not None else None
        return {**row, "practice_id": "P02", "activity_id": "H02", "contract_version": CONTRACT,
                "closed": row["closed_at"] is not None, "calls": calls}
