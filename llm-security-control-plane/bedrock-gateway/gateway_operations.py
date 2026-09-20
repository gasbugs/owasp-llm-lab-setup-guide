"""Optional credential-scoped admission and durable output-token reservations."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path


class PolicyDenied(ValueError):
    def __init__(self, reason: str, status: int = 429):
        super().__init__(reason)
        self.reason, self.status = reason, status


class GatewayOperations:
    def __init__(self, policy_path: str, database_path: str, clock=time.time):
        self.policy = json.loads(Path(policy_path).read_text())
        self.clients = self.policy["clients"]
        self.period = self.policy["window_seconds"]
        self.clock, self.database = clock, database_path
        self._validate()
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS admissions (
                id TEXT PRIMARY KEY, principal TEXT NOT NULL, window INTEGER NOT NULL,
                reserved INTEGER NOT NULL, input_tokens INTEGER, output_tokens INTEGER,
                outcome TEXT NOT NULL DEFAULT 'pending')""")
            db.execute("CREATE INDEX IF NOT EXISTS admission_window ON admissions(principal, window)")

    @classmethod
    def from_environment(cls):
        path = os.getenv("GATEWAY_OPERATIONS_POLICY")
        if not path:
            return None
        return cls(path, os.environ["GATEWAY_OPERATIONS_DATABASE"])

    def _validate(self):
        if type(self.period) is not int or self.period < 1 or not isinstance(self.clients, dict) or not self.clients:
            raise ValueError("nonempty clients and positive window_seconds required")
        hashes = set()
        for principal, policy in self.clients.items():
            if not isinstance(principal, str) or not principal or len(principal) > 64:
                raise ValueError("invalid principal")
            digest = policy["credential_sha256"]
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest) or digest in hashes:
                raise ValueError("credentials must have unique SHA-256 digests")
            hashes.add(digest)
            if not isinstance(policy["models"], list) or not policy["models"] or not all(isinstance(x, str) and x for x in policy["models"]):
                raise ValueError("nonempty model allowlist required")
            for key in ("requests", "output_tokens", "max_output_tokens", "max_input_bytes"):
                if type(policy[key]) is not int or policy[key] < 1:
                    raise ValueError("positive integer limits required")

    def _connect(self):
        return sqlite3.connect(self.database, timeout=10)

    def authenticate(self, token: str) -> str:
        digest = hashlib.sha256(token.encode()).hexdigest()
        match = None
        for principal, policy in self.clients.items():
            if hmac.compare_digest(digest, policy["credential_sha256"]):
                match = principal
        if match is None:
            raise PolicyDenied("invalid-credential", 401)
        return match

    def _window(self):
        return int(self.clock()) // self.period

    def _usage(self, db, principal, window):
        row = db.execute("""SELECT COUNT(*), COALESCE(SUM(COALESCE(output_tokens, reserved)), 0),
            COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0),
            COALESCE(SUM(CASE WHEN output_tokens IS NULL THEN reserved ELSE 0 END), 0)
            FROM admissions WHERE principal=? AND window=?""", (principal, window)).fetchone()
        return dict(zip(("requests", "output_committed", "input_tokens", "output_tokens", "output_reserved"), row))

    def admit(self, principal: str, model: str, text: str, max_tokens: int) -> str:
        policy = self.clients[principal]
        if model.partition("#")[0] not in policy["models"]:
            raise PolicyDenied("model-not-allowed", 403)
        if len(text.encode("utf-8")) > policy["max_input_bytes"]:
            raise PolicyDenied("input-byte-limit", 413)
        if not 1 <= max_tokens <= policy["max_output_tokens"]:
            raise PolicyDenied("output-request-limit", 422)
        window = self._window()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            usage = self._usage(db, principal, window)
            if usage["requests"] >= policy["requests"]:
                raise PolicyDenied("request-quota")
            if usage["output_committed"] + max_tokens > policy["output_tokens"]:
                raise PolicyDenied("output-token-quota")
            reservation = str(uuid.uuid4())
            db.execute("INSERT INTO admissions(id,principal,window,reserved) VALUES(?,?,?,?)",
                       (reservation, principal, window, max_tokens))
        return reservation

    def settle(self, reservation: str, input_tokens: int, output_tokens: int):
        if type(input_tokens) is not int or type(output_tokens) is not int or min(input_tokens, output_tokens) < 0:
            raise ValueError("invalid provider usage")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT reserved, outcome FROM admissions WHERE id=?", (reservation,)).fetchone()
            if row is None or row[1] != "pending":
                raise ValueError("reservation absent or already finalized")
            if output_tokens > row[0]:
                raise ValueError("provider exceeded reserved output ceiling")
            db.execute("UPDATE admissions SET input_tokens=?, output_tokens=?, outcome='complete' WHERE id=?",
                       (input_tokens, output_tokens, reservation))

    def uncertain(self, reservation: str):
        with self._connect() as db:
            db.execute("UPDATE admissions SET outcome='uncertain' WHERE id=? AND outcome='pending'", (reservation,))

    def usage(self, principal: str):
        window = self._window()
        with self._connect() as db:
            usage = self._usage(db, principal, window)
        return {"principal": principal, "window_seconds": self.period,
                "window_start": window * self.period,
                "limits": {k: v for k, v in self.clients[principal].items() if k != "credential_sha256"},
                **usage}
