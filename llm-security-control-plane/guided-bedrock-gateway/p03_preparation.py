"""Durable P03 preparation journal; no AWS calls or automatic crash recovery.

A failed or interrupted preparation must not expose a previously ready binding.
Cloud creation and ownership auditing remain the caller's server-owned work.
"""
import json
import math
import sqlite3
import time
from uuid import UUID

from p03_ledger import LedgerError
from p03_resource_contract import template
from p03_suites import encode, resource_snapshot


class PreparationStore:
    def __init__(self, path, *, now=time.time):
        self.path, self.now = str(path), now
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS resource_state "
                       "(logical_name TEXT PRIMARY KEY, state_json TEXT NOT NULL)")
            db.execute("""CREATE TABLE IF NOT EXISTS p03_preparations (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_id TEXT NOT NULL UNIQUE, account_id TEXT NOT NULL,
                template_digest TEXT NOT NULL, started_at REAL NOT NULL,
                finished_at REAL, state TEXT NOT NULL, snapshot_json TEXT)""")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS p03_one_preparation "
                       "ON p03_preparations(state) WHERE state='preparing'")
            db.execute("CREATE TABLE IF NOT EXISTS p03_preparation_evidence "
                       "(operation_id TEXT PRIMARY KEY, evidence_json TEXT NOT NULL)")

    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    def stamp(self):
        value = self.now()
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise LedgerError(409)
        return value

    def begin(self, operation_id, account_id):
        try:
            if str(UUID(operation_id)) != operation_id:
                raise ValueError()
            specification = template(account_id)
        except (ValueError, TypeError, AttributeError):
            raise LedgerError(422) from None
        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                previous = db.execute("SELECT account_id FROM p03_preparations ORDER BY sequence DESC LIMIT 1").fetchone()
                if previous and previous["account_id"] != account_id:
                    raise LedgerError(409)
                db.execute("INSERT INTO p03_preparations "
                           "(operation_id,account_id,template_digest,started_at,state) VALUES(?,?,?,?,'preparing')",
                           (operation_id, account_id, specification["template_digest"], self.stamp()))
        except sqlite3.IntegrityError:
            raise LedgerError(409) from None
        return specification

    def publish(self, operation_id, snapshot, *, evidence=None):
        snapshot = resource_snapshot(snapshot)
        if snapshot["provider_mode"] != "aws":
            raise LedgerError(409)
        proof = None if evidence is None else encode(evidence)
        if proof is not None and (not isinstance(evidence, dict) or len(proof.encode()) > 65536):
            raise LedgerError(409)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM p03_preparations WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None or row["state"] != "preparing":
                raise LedgerError(409)
            specification = template(row["account_id"])
            binding = snapshot["binding"]
            prefix = "s3://" + specification["source_bucket"] + "/" + specification["source_prefix"]
            finished = self.stamp()
            if (row["template_digest"] != specification["template_digest"]
                    or binding["region"] != specification["region"]
                    or binding["source_uri_prefix"] != prefix
                    or binding["current_job_id"] != "p03-" + UUID(operation_id).hex
                    or snapshot["source_uris"] != [prefix + "current-policy.md"]
                    or not 0 <= finished - row["started_at"] <= 900):
                raise LedgerError(409)
            payload = encode(snapshot)
            db.execute("INSERT INTO resource_state VALUES('p03',?) "
                       "ON CONFLICT(logical_name) DO UPDATE SET state_json=excluded.state_json", (payload,))
            db.execute("UPDATE p03_preparations SET state='ready',finished_at=?,snapshot_json=? WHERE operation_id=?",
                       (finished, payload, operation_id))
            if proof is not None:
                db.execute("INSERT INTO p03_preparation_evidence VALUES(?,?)", (operation_id, proof))
        return snapshot

    def read(self, operation_id):
        with self.connect() as db:
            db.execute("BEGIN")
            row = db.execute("SELECT * FROM p03_preparations WHERE operation_id=?", (operation_id,)).fetchone()
            proof = db.execute("SELECT evidence_json FROM p03_preparation_evidence WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None:
                raise LedgerError(404)
            result = dict(row)
            result.pop("sequence")
            raw = result.pop("snapshot_json")
            result["resources"] = json.loads(raw) if raw is not None else None
            result["evidence"] = json.loads(proof[0]) if proof is not None else None
            return {"practice_id": "P03", **result}

    def fail(self, operation_id):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM p03_preparations WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None or row["state"] != "preparing":
                raise LedgerError(409)
            finished = self.stamp()
            if finished < row["started_at"]:
                raise LedgerError(409)
            db.execute("UPDATE p03_preparations SET state='error',finished_at=? WHERE operation_id=?",
                       (finished, operation_id))

    def resources(self):
        with self.connect() as db:
            db.execute("BEGIN")
            row = db.execute("SELECT * FROM p03_preparations ORDER BY sequence DESC LIMIT 1").fetchone()
            current = db.execute("SELECT state_json FROM resource_state WHERE logical_name='p03'").fetchone()
            if (row is None or row["state"] != "ready" or current is None
                    or current[0] != row["snapshot_json"]
                    or row["template_digest"] != template(row["account_id"])["template_digest"]):
                raise LedgerError(409)
            return resource_snapshot(json.loads(current[0]))

    def run(self, operation_id, account_id, prepare):
        specification = self.begin(operation_id, account_id)
        try:
            snapshot = prepare(specification, operation_id)
            return self.publish(operation_id, snapshot)
        except Exception:
            self.fail(operation_id)
            raise LedgerError(502) from None
