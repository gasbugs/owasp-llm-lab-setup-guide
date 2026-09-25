"""P04 durable case mappings; resource_reader only inspects prepared local state."""
import hashlib
import json
import math
import re
import sqlite3
import time

from p04_contract import ACTIVITY_ID, CONTRACT_VERSION, PRACTICE_ID, canonical, expected_arguments
from p04_ledger import LedgerError, digest, identifier


def resource_snapshot(value):
    try:
        if set(value) != {"provider_mode", "guardrail", "guardrail_arn", "policy_digest"}:
            raise ValueError()
        result = json.loads(canonical(value))
        expected_arguments({"operation": "apply_guardrail", "text": "reference"}, result["guardrail"])
        digest(result["policy_digest"])
        if result["provider_mode"] == "contract":
            if result["guardrail_arn"] is not None or result["guardrail"]["guardrailIdentifier"] != "p04contract":
                raise ValueError()
        elif result["provider_mode"] == "aws":
            arn = result["guardrail_arn"]
            if (not isinstance(arn, str)
                    or not re.fullmatch(r"arn:aws:bedrock:us-east-1:[0-9]{12}:guardrail/[a-z0-9]+", arn)
                    or arn.rsplit("/", 1)[-1] != result["guardrail"]["guardrailIdentifier"]):
                raise ValueError()
        else:
            raise ValueError()
        return result
    except (ValueError, TypeError, KeyError, LedgerError):
        raise LedgerError(409) from None


class SuiteStore:
    def __init__(self, path, cases, resource_reader, *, now=time.time):
        self.path, self.resource_reader, self.now = str(path), resource_reader, now
        contracts = json.loads(canonical(cases))
        if (not isinstance(contracts, list) or not 1 <= len(contracts) <= 32
                or any(not isinstance(case, dict)
                       or set(case) != {"case_id", "backend", "body", "expected", "provider_error"}
                       or not isinstance(case["case_id"], str)
                       or not re.fullmatch(r"[a-z0-9_-]{1,64}", case["case_id"])
                       or case["backend"] not in ("provider", "contract")
                       or case["expected"] not in ("returned", "rejected", "service_error")
                       or type(case["provider_error"]) is not bool for case in contracts)
                or len({case["case_id"] for case in contracts}) != len(contracts)):
            raise ValueError("server-owned case definitions required")
        self.contracts = {case["case_id"]: case for case in contracts}
        self.contract_digest = hashlib.sha256(canonical(contracts)).hexdigest()
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS p04_suites (
                suite_id TEXT PRIMARY KEY, contract_digest TEXT NOT NULL,
                started_at REAL NOT NULL, prepared_at REAL, state TEXT NOT NULL, snapshot_json TEXT)""")
            db.execute("""CREATE TABLE IF NOT EXISTS p04_suite_cases (
                execution_id TEXT PRIMARY KEY, suite_id TEXT NOT NULL, case_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL, UNIQUE(suite_id, case_id))""")

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def stamp(self):
        value = self.now()
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise LedgerError(409)
        return value

    def prepare(self, suite_id, rows):
        identifier(suite_id)
        if (not isinstance(rows, list) or len(rows) != len(self.contracts)
                or any(not isinstance(row, dict) or set(row) != {"case_id", "execution_id"} for row in rows)
                or [row["case_id"] for row in rows] != list(self.contracts)):
            raise LedgerError(422)
        for row in rows:
            identifier(row["execution_id"])
        if len({row["execution_id"] for row in rows}) != len(rows):
            raise LedgerError(422)
        started = self.stamp()
        try:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO p04_suites VALUES(?,?,?,NULL,'preparing',NULL)",
                           (suite_id, self.contract_digest, started))
                for ordinal, row in enumerate(rows):
                    db.execute("INSERT INTO p04_suite_cases VALUES(?,?,?,?)",
                               (row["execution_id"], suite_id, row["case_id"], ordinal))
        except sqlite3.IntegrityError:
            raise LedgerError(409) from None
        try:
            snapshot = resource_snapshot(self.resource_reader())
            finished = self.stamp()
            if not 0 <= finished - started < 30:
                raise LedgerError(409)
            with self.connect() as db:
                db.execute("UPDATE p04_suites SET state='prepared',prepared_at=?,snapshot_json=? WHERE suite_id=?",
                           (finished, canonical(snapshot).decode(), suite_id))
        except Exception:
            with self.connect() as db:
                db.execute("UPDATE p04_suites SET state='error' WHERE suite_id=?", (suite_id,))
            raise LedgerError(409) from None
        return {"suite_id": suite_id, "contract_version": CONTRACT_VERSION, "prepared": True,
                "mapping_digest": hashlib.sha256(canonical(rows)).hexdigest()}

    def read(self, suite_id):
        identifier(suite_id)
        with self.connect() as db:
            db.execute("BEGIN")
            row = db.execute("SELECT * FROM p04_suites WHERE suite_id=?", (suite_id,)).fetchone()
            if row is None:
                raise LedgerError(404)
            result = dict(row)
            result["cases"] = [dict(case) for case in db.execute(
                "SELECT execution_id,case_id FROM p04_suite_cases WHERE suite_id=? ORDER BY ordinal", (suite_id,))]
        raw = result.pop("snapshot_json")
        result["resources"] = json.loads(raw) if raw is not None else None
        return {"practice_id": PRACTICE_ID, "activity_id": ACTIVITY_ID,
                "contract_version": CONTRACT_VERSION, **result}

    def lookup(self, suite_id, execution_id):
        identifier(execution_id)
        root = self.read(suite_id)
        if (root["state"] != "prepared" or root["contract_digest"] != self.contract_digest
                or not 0 <= self.stamp() - root["started_at"] < 900):
            raise LedgerError(409)
        row = next((row for row in root["cases"] if row["execution_id"] == execution_id), None)
        if row is None:
            raise LedgerError(404)
        snapshot = resource_snapshot(root["resources"])
        if resource_snapshot(self.resource_reader()) != snapshot:
            raise LedgerError(409)
        return {"case": json.loads(canonical(self.contracts[row["case_id"]])), "resources": snapshot}

    def resolve(self, suite_id, execution_id):
        row = self.lookup(suite_id, execution_id)
        case, resources = row["case"], row["resources"]
        return {"body": case["body"], "guardrail": resources["guardrail"],
                "resource_digest": hashlib.sha256(canonical(resources)).hexdigest(),
                "provider_mode": resources["provider_mode"] if case["backend"] == "provider" else "contract"}

    def inspect(self, suite_id):
        """Read registered local state only; this is not an AWS policy audit."""
        root = self.read(suite_id)
        observed = self.stamp()
        if (root["state"] != "prepared" or root["contract_digest"] != self.contract_digest
                or not 0 <= observed - root["started_at"] < 900):
            raise LedgerError(409)
        current = resource_snapshot(self.resource_reader())
        if current != resource_snapshot(root["resources"]):
            raise LedgerError(409)
        return {"suite_id": suite_id, "scope": "registered-resource-state",
                "observed_at": observed, "resources": current}
