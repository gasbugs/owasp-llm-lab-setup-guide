"""P04 case mapping persistence and scope, using local SQLite and no AWS."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
GATEWAY = ROOT / "llm-security-control-plane/guided-bedrock-gateway"
spec = importlib.util.spec_from_file_location("p04_cases_test",
    ROOT / "llm-security-control-plane/guided-labs/h04-bedrock-guardrail/cases.py")
case_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(case_module)
sys.path.insert(0, str(GATEWAY))
try:
    from p04_ledger import LedgerError
    from p04_suites import SuiteStore, resource_snapshot
finally:
    sys.path.remove(str(GATEWAY))


class SuiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = 1000.0
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.resources = {"provider_mode": "aws", "guardrail": {
            "guardrailIdentifier": "p04fixture", "guardrailVersion": "DRAFT"},
            "guardrail_arn": "arn:aws:bedrock:us-east-1:000000000000:guardrail/p04fixture",
            "policy_digest": "a" * 64}
        self.reader = Mock(side_effect=lambda: deepcopy(self.resources))
        self.cases = case_module.cases()
        self.store = SuiteStore(self.path, self.cases, self.reader, now=lambda: self.clock)
        self.suite = str(uuid4())
        self.rows = [{"case_id": case["case_id"], "execution_id": str(uuid4())} for case in self.cases]

    def prepare(self):
        return self.store.prepare(self.suite, self.rows)

    def test_cases_cover_native_paths_and_synthetic_error_boundaries(self):
        self.assertEqual(len(self.cases), 27)
        self.assertEqual(sum(row["backend"] == "provider" for row in self.cases), 4)
        self.assertEqual(sum(row["expected"] == "rejected" for row in self.cases), 18)
        self.assertEqual(sum(row["provider_error"] for row in self.cases), 2)
        for row in self.cases:
            if row["backend"] == "provider":
                self.assertEqual(row["expected"], "returned")
                self.assertFalse(row["provider_error"])

    def test_prepare_reopen_resolve_and_read_only_snapshot(self):
        prepared = self.prepare()
        reopened = SuiteStore(self.path, case_module.cases(), self.reader, now=lambda: self.clock)
        self.assertTrue(prepared["prepared"])
        self.assertEqual(self.store.read(self.suite), reopened.read(self.suite))
        for row, expected in zip(self.rows, self.cases):
            resolved = reopened.resolve(self.suite, row["execution_id"])
            self.assertEqual(resolved["body"], expected["body"])
            self.assertEqual(resolved["guardrail"], self.resources["guardrail"])
            self.assertEqual(resolved["provider_mode"],
                             "aws" if expected["backend"] == "provider" else "contract")

    def test_contract_mode_never_relabels_native_cases_as_aws(self):
        self.resources = {"provider_mode": "contract",
                          "guardrail": {"guardrailIdentifier": "p04contract", "guardrailVersion": "DRAFT"},
                          "guardrail_arn": None, "policy_digest": "c" * 64}
        self.prepare()
        for row in self.rows:
            self.assertEqual(self.store.resolve(self.suite, row["execution_id"])["provider_mode"], "contract")

    def test_incomplete_reordered_duplicate_and_caller_content_are_rejected(self):
        variants = [self.rows[:-1], list(reversed(self.rows))]
        duplicate = deepcopy(self.rows)
        duplicate[-1]["execution_id"] = duplicate[0]["execution_id"]
        variants.append(duplicate)
        extra = deepcopy(self.rows)
        extra[0]["body"] = "caller case"
        variants.append(extra)
        for rows in variants:
            with self.assertRaises(LedgerError):
                self.store.prepare(self.suite, rows)
        self.reader.assert_not_called()

    def test_duplicate_suite_and_cross_suite_execution_reuse_are_atomic(self):
        self.prepare()
        before = self.store.read(self.suite)
        with self.assertRaises(LedgerError):
            self.prepare()
        other = str(uuid4())
        with self.assertRaises(LedgerError):
            self.store.prepare(other, self.rows)
        with self.assertRaises(LedgerError) as error:
            self.store.read(other)
        self.assertEqual(error.exception.status, 404)
        self.assertEqual(self.store.read(self.suite), before)
        self.assertEqual(self.reader.call_count, 1)

    def test_failed_resource_preparation_is_preserved_and_not_retried(self):
        self.reader.side_effect = RuntimeError("private failure")
        with self.assertRaises(LedgerError):
            self.prepare()
        self.assertEqual(self.store.read(self.suite)["state"], "error")
        with self.assertRaises(LedgerError):
            self.prepare()
        self.assertEqual(self.reader.call_count, 1)
        with self.assertRaises(LedgerError):
            self.store.resolve(self.suite, self.rows[0]["execution_id"])

    def test_pending_and_expired_suites_cannot_be_resolved(self):
        self.prepare()
        for value in (999, 1900):
            self.clock = value
            with self.assertRaises(LedgerError):
                self.store.resolve(self.suite, self.rows[0]["execution_id"])
        self.clock = 1000
        with self.store.connect() as db:
            db.execute("UPDATE p04_suites SET state='preparing' WHERE suite_id=?", (self.suite,))
        with self.assertRaises(LedgerError):
            self.store.resolve(self.suite, self.rows[0]["execution_id"])

    def test_changed_contract_or_resources_refuses_old_execution(self):
        self.prepare()
        cases = deepcopy(self.cases)
        cases[0]["body"]["text"] = "new fixture"
        changed = SuiteStore(self.path, cases, self.reader, now=lambda: self.clock)
        with self.assertRaises(LedgerError):
            changed.resolve(self.suite, self.rows[0]["execution_id"])
        self.resources["policy_digest"] = "b" * 64
        with self.assertRaises(LedgerError):
            self.store.resolve(self.suite, self.rows[0]["execution_id"])

    def test_wrong_suite_execution_pair_is_not_resolved(self):
        self.prepare()
        with self.assertRaises(LedgerError):
            self.store.resolve(self.suite, str(uuid4()))
        with self.assertRaises(LedgerError):
            self.store.resolve(str(uuid4()), self.rows[0]["execution_id"])

    def test_source_case_mutation_does_not_change_registered_contract(self):
        self.cases[0]["body"]["text"] = "mutated outside store"
        self.prepare()
        self.assertNotEqual(self.store.resolve(self.suite, self.rows[0]["execution_id"])["body"],
                            self.cases[0]["body"])

    def test_native_arn_region_identifier_and_contract_namespace_must_match(self):
        for key, value in (("guardrail_arn", "arn:aws:bedrock:eu-west-1:000000000000:guardrail/p04fixture"),
                           ("guardrail_arn", "arn:aws:bedrock:us-east-1:000000000000:guardrail/other"),
                           ("policy_digest", "not-digest"), ("provider_mode", "contract")):
            resources = deepcopy(self.resources)
            resources[key] = value
            with self.assertRaises(LedgerError):
                resource_snapshot(resources)

    def test_slow_preparation_is_error_and_never_silently_ready(self):
        def slow():
            self.clock += 30
            return self.resources
        self.reader.side_effect = slow
        with self.assertRaises(LedgerError):
            self.prepare()
        self.assertEqual(self.store.read(self.suite)["state"], "error")


if __name__ == "__main__":
    unittest.main()
