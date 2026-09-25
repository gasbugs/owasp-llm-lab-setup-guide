"""P04 preparation journal. Interrupted/failed preparation never exposes old readiness."""
import json
import math
import sqlite3
import time

from p04_contract import canonical
from p04_ledger import LedgerError, identifier
from p04_resource_contract import template
from p04_suites import resource_snapshot


class PreparationStore:
    def __init__(self, path, *, now=time.time):
        self.path, self.now = str(path), now
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS p04_preparations (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL UNIQUE,
                account_id TEXT NOT NULL, template_digest TEXT NOT NULL, started_at REAL NOT NULL,
                finished_at REAL, state TEXT NOT NULL, snapshot_json TEXT, evidence_json TEXT)""")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS p04_one_preparation "
                       "ON p04_preparations(state) WHERE state='preparing'")

    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    def stamp(self):
        value = self.now()
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise LedgerError(409)
        return value

    def account(self):
        with self.connect() as db:
            row = db.execute('SELECT account_id FROM p04_preparations ORDER BY sequence DESC LIMIT 1').fetchone()
        return row['account_id'] if row is not None else None

    def begin(self, operation_id, account_id):
        identifier(operation_id)
        specification = template(account_id)
        try:
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                previous = db.execute('SELECT account_id FROM p04_preparations ORDER BY sequence DESC LIMIT 1').fetchone()
                if previous is not None and previous['account_id'] != account_id:
                    raise LedgerError(409)
                db.execute("INSERT INTO p04_preparations "
                           "(operation_id,account_id,template_digest,started_at,state) VALUES(?,?,?,?,'preparing')",
                           (operation_id, account_id, specification['template_digest'], self.stamp()))
        except sqlite3.IntegrityError:
            raise LedgerError(409) from None
        return specification

    def publish(self, operation_id, snapshot, evidence):
        identifier(operation_id)
        snapshot = resource_snapshot(snapshot)
        if not isinstance(evidence, dict) or set(evidence) != {'aws_request_ids', 'created'}:
            raise LedgerError(409)
        ids = evidence['aws_request_ids']
        if (type(evidence['created']) is not bool or not isinstance(ids, list) or not 3 <= len(ids) <= 200
                or any(not isinstance(value, str) or not value.isascii() or not 1 <= len(value) <= 256 for value in ids)
                or len(set(ids)) != len(ids)):
            raise LedgerError(409)
        proof = canonical(evidence).decode()
        if len(proof.encode()) > 65536:
            raise LedgerError(409)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM p04_preparations WHERE operation_id=?', (operation_id,)).fetchone()
            if row is None or row['state'] != 'preparing':
                raise LedgerError(409)
            specification = template(row['account_id'])
            finished = self.stamp()
            if (snapshot['provider_mode'] != 'aws'
                    or snapshot['policy_digest'] != specification['template_digest']
                    or row['template_digest'] != specification['template_digest']
                    or snapshot['guardrail_arn'].split(':')[4] != row['account_id']
                    or not 0 <= finished - row['started_at'] <= 300):
                raise LedgerError(409)
            db.execute("UPDATE p04_preparations SET state='ready',finished_at=?,snapshot_json=?,evidence_json=? "
                       "WHERE operation_id=?", (finished, canonical(snapshot).decode(), proof, operation_id))
        return self.read(operation_id)

    def fail(self, operation_id):
        identifier(operation_id)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM p04_preparations WHERE operation_id=?', (operation_id,)).fetchone()
            finished = self.stamp()
            if row is None or row['state'] != 'preparing' or finished < row['started_at']:
                raise LedgerError(409)
            db.execute("UPDATE p04_preparations SET state='error',finished_at=? WHERE operation_id=?",
                       (finished, operation_id))

    def read(self, operation_id):
        identifier(operation_id)
        with self.connect() as db:
            row = db.execute('SELECT * FROM p04_preparations WHERE operation_id=?', (operation_id,)).fetchone()
        if row is None:
            raise LedgerError(404)
        result = dict(row)
        result.pop('sequence')
        for column, key in (('snapshot_json', 'resources'), ('evidence_json', 'evidence')):
            raw = result.pop(column)
            result[key] = json.loads(raw) if raw is not None else None
        return {'practice_id': 'P04', **result}

    def resources(self):
        with self.connect() as db:
            row = db.execute('SELECT * FROM p04_preparations ORDER BY sequence DESC LIMIT 1').fetchone()
        if row is None or row['state'] != 'ready' or row['snapshot_json'] is None or row['evidence_json'] is None:
            raise LedgerError(409)
        specification = template(row['account_id'])
        snapshot = resource_snapshot(json.loads(row['snapshot_json']))
        if (row['template_digest'] != specification['template_digest']
                or snapshot['policy_digest'] != specification['template_digest']
                or snapshot['provider_mode'] != 'aws'
                or snapshot['guardrail_arn'].split(':')[4] != row['account_id']):
            raise LedgerError(409)
        return snapshot
