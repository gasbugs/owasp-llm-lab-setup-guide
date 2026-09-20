"""Local synthetic-action approval exercise; no external actions are executed."""

import hashlib
import hmac
import json
import sqlite3
import time
import uuid


class ApprovalDenied(ValueError):
    pass


class ApprovalStore:
    def __init__(self, database, credentials, clock=time.time):
        self.database, self.credentials, self.clock = database, credentials, clock
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY, requester TEXT, payload TEXT, expires REAL,
                state TEXT, reviewer TEXT)""")
            db.execute("CREATE TABLE IF NOT EXISTS effects (approval_id TEXT PRIMARY KEY, notice TEXT)")

    def connect(self):
        return sqlite3.connect(self.database, timeout=10)

    def actor(self, token):
        digest = hashlib.sha256(token.encode()).hexdigest()
        for subject, entry in self.credentials.items():
            if hmac.compare_digest(digest, entry["credential_sha256"]):
                return subject, entry["role"]
        raise ApprovalDenied("authentication-required")

    @staticmethod
    def payload(action):
        if set(action) != {"kind", "notice"} or action["kind"] != "publish_training_notice":
            raise ApprovalDenied("action-not-allowed")
        if not isinstance(action["notice"], str) or not 1 <= len(action["notice"]) <= 120:
            raise ApprovalDenied("invalid-notice")
        return json.dumps(action, sort_keys=True, ensure_ascii=False)

    def propose(self, token, action):
        subject, role = self.actor(token)
        if role != "requester":
            raise ApprovalDenied("requester-role-required")
        payload, identifier = self.payload(action), str(uuid.uuid4())
        with self.connect() as db:
            db.execute("INSERT INTO approvals VALUES(?,?,?,?,?,NULL)",
                       (identifier, subject, payload, self.clock() + 300, "pending"))
        return identifier

    def review(self, token, identifier, approve):
        subject, role = self.actor(token)
        if role != "reviewer" or type(approve) is not bool:
            raise ApprovalDenied("reviewer-role-required")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT requester, expires, state FROM approvals WHERE id=?", (identifier,)).fetchone()
            if row is None or row[0] == subject or row[1] <= self.clock() or row[2] != "pending":
                raise ApprovalDenied("approval-not-reviewable")
            db.execute("UPDATE approvals SET state=?, reviewer=? WHERE id=?",
                       ("approved" if approve else "denied", subject, identifier))

    def execute(self, token, identifier, action):
        subject, role = self.actor(token)
        payload = self.payload(action)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT requester, payload, expires, state FROM approvals WHERE id=?", (identifier,)).fetchone()
            if role != "requester" or row is None or row[0] != subject:
                raise ApprovalDenied("requester-mismatch")
            if row[1] != payload or row[2] <= self.clock() or row[3] != "approved":
                raise ApprovalDenied("approval-invalid-expired-or-consumed")
            db.execute("INSERT INTO effects VALUES(?,?)", (identifier, action["notice"]))
            db.execute("UPDATE approvals SET state='consumed' WHERE id=?", (identifier,))
        return {"decision": "allow", "effect": "local-training-notice", "external_action_called": False}

    def effect_count(self):
        with self.connect() as db:
            return db.execute("SELECT COUNT(*) FROM effects").fetchone()[0]
