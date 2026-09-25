"""Durable P03 mappings with server-owned resources and explicit contract fixtures.

resource_reader must only inspect already prepared P03 resources, never create
resources or start ingestion. Provider construction stays outside this store.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
import math
import sqlite3
import time
from uuid import uuid4

from p03_backend import BedrockSearchBackend, Binding
from p03_ledger import LedgerError, identifier

CONTRACT_URI = "s3://p03-contract/h03/knowledge/current-policy.md"


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)


def resource_snapshot(value):
    try:
        if set(value) != {"provider_mode", "binding", "source_uris"}:
            raise ValueError()
        value = json.loads(encode(value))
        if value["provider_mode"] == "contract":
            if value["binding"] is not None or value["source_uris"] != [CONTRACT_URI]:
                raise ValueError()
        elif value["provider_mode"] == "aws":
            binding = Binding(**value["binding"])
            if value["binding"] != asdict(binding):
                raise ValueError()
            uris = value["source_uris"]
            if (not isinstance(uris, list) or not 1 <= len(uris) <= 16
                    or any(not isinstance(uri, str) or not uri.startswith(binding.source_uri_prefix)
                           or uri == binding.source_uri_prefix for uri in uris) or len(set(uris)) != len(uris)):
                raise ValueError()
        else:
            raise ValueError()
        return value
    except (ValueError, TypeError, KeyError, RuntimeError):
        raise LedgerError(409) from None


class SuiteStore:
    def __init__(self, path, cases, resource_reader, *, now=time.time):
        self.path, self.resource_reader, self.now = str(path), resource_reader, now
        contracts = json.loads(encode(cases))
        if (not isinstance(contracts, list) or not 1 <= len(contracts) <= 32
                or any(not isinstance(case, dict) or not isinstance(case.get("case_id"), str)
                       or not case["case_id"] or case.get("backend") not in {"provider", "contract"}
                       for case in contracts)
                or len({case["case_id"] for case in contracts}) != len(contracts)):
            raise ValueError("server-owned cases required")
        self.contracts = {case["case_id"]: case for case in contracts}
        self.contract_digest = hashlib.sha256(encode(contracts).encode()).hexdigest()
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS p03_suites (
                suite_id TEXT PRIMARY KEY, contract_digest TEXT NOT NULL,
                started_at REAL NOT NULL, prepared_at REAL, state TEXT NOT NULL, snapshot_json TEXT)""")
            db.execute("""CREATE TABLE IF NOT EXISTS p03_suite_cases (
                execution_id TEXT PRIMARY KEY, suite_id TEXT NOT NULL, case_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL, current_job_id TEXT NOT NULL UNIQUE,
                UNIQUE(suite_id, case_id))""")

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
                db.execute("INSERT INTO p03_suites VALUES(?,?,?,NULL,'preparing',NULL)",
                           (suite_id, self.contract_digest, started))
                for ordinal, row in enumerate(rows):
                    db.execute("INSERT INTO p03_suite_cases VALUES(?,?,?,?,?)", (
                        row["execution_id"], suite_id, row["case_id"], ordinal, "p03-" + uuid4().hex))
        except sqlite3.IntegrityError:
            raise LedgerError(409) from None
        try:
            snapshot = resource_snapshot(self.resource_reader())
            finished = self.stamp()
            if not 0 <= finished - started < 30:
                raise LedgerError(409)
            with self.connect() as db:
                db.execute("UPDATE p03_suites SET state='prepared', prepared_at=?, snapshot_json=? WHERE suite_id=?",
                           (finished, encode(snapshot), suite_id))
        except Exception:
            with self.connect() as db:
                db.execute("UPDATE p03_suites SET state='error' WHERE suite_id=?", (suite_id,))
            raise LedgerError(409) from None

    def read(self, suite_id):
        identifier(suite_id)
        with self.connect() as db:
            db.execute("BEGIN")
            row = db.execute("SELECT * FROM p03_suites WHERE suite_id=?", (suite_id,)).fetchone()
            if row is None:
                raise LedgerError(404)
            result = dict(row)
            result["cases"] = [dict(case) for case in db.execute(
                "SELECT execution_id,case_id,current_job_id FROM p03_suite_cases WHERE suite_id=? ORDER BY ordinal", (suite_id,))]
        raw = result.pop("snapshot_json")
        result["resources"] = json.loads(raw) if raw is not None else None
        return {"practice_id": "P03", "activity_id": "H03", "contract_version": "p03-search-v1", **result}

    def lookup(self, *, suite_id=None, execution_id=None, job_id=None):
        with self.connect() as db:
            row = (db.execute("SELECT * FROM p03_suite_cases WHERE current_job_id=?", (job_id,)).fetchone()
                   if job_id is not None else db.execute(
                       "SELECT * FROM p03_suite_cases WHERE suite_id=? AND execution_id=?", (suite_id, execution_id)).fetchone())
        if row is None:
            raise LedgerError(404)
        root = self.read(row["suite_id"])
        if (root["state"] != "prepared" or root["contract_digest"] != self.contract_digest
                or not 0 <= self.stamp() - root["started_at"] < 240):
            raise LedgerError(409)
        return {**dict(row), "case": deepcopy(self.contracts[row["case_id"]]),
                "resources": resource_snapshot(root["resources"])}

    def resolve(self, suite_id, execution_id):
        return self.lookup(suite_id=suite_id, execution_id=execution_id)["current_job_id"]

    def current_resources(self, expected):
        actual = resource_snapshot(self.resource_reader())
        if actual != expected:
            raise LedgerError(409)
        return actual

    def inspect_resources(self, suite_id):
        root = self.read(suite_id)
        if root["state"] != "prepared" or root["contract_digest"] != self.contract_digest:
            raise LedgerError(409)
        resources = self.current_resources(resource_snapshot(root["resources"]))
        return {"scope": "registered-resource-state", "suite_id": suite_id,
                "observed_at": self.stamp(), "resources": resources}


class ContractBackend:
    """Synthetic protocol responses, explicitly distinct from AWS observations."""
    def __init__(self, case, job):
        self.case, self.job = deepcopy(case), job

    def job_status(self, job):
        if job != self.job or self.case.get("failed_operation") == "job_status":
            raise LedgerError(502)
        response = {"provider_mode": "contract"}
        observed = self.case.get("observed_job", "current")
        if observed != "missing":
            response["ingestion_job_id"] = job if observed == "current" else "previous-job"
        if self.case["backend"] == "provider" or "status" in self.case:
            response["status"] = deepcopy(self.case.get("status", "COMPLETE"))
        return response

    def retrieve(self, job):
        if (job != self.job or self.case.get("failed_operation") is not None
                or self.case.get("status", "COMPLETE" if self.case["backend"] == "provider" else None) != "COMPLETE"
                or self.case.get("observed_job", "current") != "current"):
            raise LedgerError(502)
        return {"provider_mode": "contract", "ingestion_job_id": job,
                "results": [{"location": {"type": "S3", "s3Location": {"uri": CONTRACT_URI}},
                             "content": {"text": "Synthetic current policy"}, "score": 0.8}]}


class RegisteredBackend:
    def __init__(self, store, provider_factory):
        self.store, self.provider_factory = store, provider_factory

    def backend(self, job):
        row = self.store.lookup(job_id=job)
        if row["case"]["backend"] == "contract" or row["resources"]["provider_mode"] == "contract":
            return ContractBackend(row["case"], job)
        self.store.current_resources(row["resources"])
        return self.provider_factory(deepcopy(row["resources"]), job)

    def job_status(self, job):
        return self.backend(job).job_status(job)

    def retrieve(self, job):
        return self.backend(job).retrieve(job)


def bedrock_factory(store, agent, runtime):
    """Construct SDK adapters with both the suite alias and original job binding."""
    def create(resources, job):
        binding = replace(Binding(**resources["binding"]), current_job_id=job)

        def current():
            snapshot = store.current_resources(resources)
            return replace(Binding(**snapshot["binding"]), current_job_id=job)

        return BedrockSearchBackend(binding, current, agent, runtime)
    return create
