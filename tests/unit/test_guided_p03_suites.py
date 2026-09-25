"""Persistent case registration; no resource creation or live AWS requests."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock
from uuid import uuid4

import test_guided_p03_run_server as run_tests
import test_guided_p03_backend as backend_tests

module = run_tests.suites
LedgerError = run_tests.flow.gateway.ledger_module.LedgerError


class SuiteTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "suites.sqlite3"
        self.clock = [1000.0]
        self.snapshot = {"provider_mode": "contract", "binding": None, "source_uris": [module.CONTRACT_URI]}
        self.reader = Mock(side_effect=lambda: deepcopy(self.snapshot))
        self.store = self.reopen()
        self.suite = str(uuid4())
        self.rows = [{"case_id": case["case_id"], "execution_id": str(uuid4())} for case in run_tests.cases.cases()]

    def reopen(self):
        return module.SuiteStore(self.path, run_tests.cases.cases(), self.reader, now=lambda: self.clock[0])

    def prepare(self):
        self.store.prepare(self.suite, self.rows)
        return self.store.read(self.suite)

    def test_prepared_mapping_survives_restart_without_resource_writes(self):
        root = self.prepare()
        restarted = self.reopen()
        self.assertEqual(restarted.read(self.suite), root)
        self.assertEqual(root["state"], "prepared")
        self.assertEqual(len({row["current_job_id"] for row in root["cases"]}), 19)
        for row in root["cases"]:
            self.assertEqual(restarted.resolve(self.suite, row["execution_id"]), row["current_job_id"])
        self.reader.assert_called_once_with()
        self.assertNotIn("task_completed", root)

    def test_missing_reordered_duplicate_or_extra_mapping_is_rejected_before_reader(self):
        invalid = [self.rows[:-1], list(reversed(self.rows)), self.rows + [self.rows[0]],
                   [{**row, "current_job_id": "client"} for row in self.rows],
                   [{**row, "execution_id": self.rows[0]["execution_id"]} for row in self.rows]]
        for rows in invalid:
            with self.assertRaises(LedgerError):
                self.store.prepare(self.suite, rows)
        self.reader.assert_not_called()

    def test_execution_id_cannot_be_reassigned_to_another_suite(self):
        original = self.prepare()
        with self.assertRaises(LedgerError):
            self.store.prepare(str(uuid4()), self.rows)
        with self.assertRaises(LedgerError):
            self.store.prepare(self.suite, self.rows)
        self.assertEqual(self.store.read(self.suite), original)
        self.reader.assert_called_once_with()

    def test_concurrent_duplicate_registration_has_one_winner(self):
        def attempt(_):
            try:
                self.reopen().prepare(self.suite, self.rows)
                return "prepared"
            except LedgerError as error:
                return error.status
        with ThreadPoolExecutor(max_workers=6) as pool:
            statuses = list(pool.map(attempt, range(6)))
        self.assertEqual(statuses.count("prepared"), 1)
        self.assertEqual(statuses.count(409), 5)
        self.reader.assert_called_once_with()

    def test_preparation_failure_is_durable_and_cannot_authorize_registration(self):
        self.reader.side_effect = RuntimeError("private credential diagnostics")
        with self.assertRaises(LedgerError) as caught:
            self.store.prepare(self.suite, self.rows)
        self.assertNotIn("private", str(caught.exception))
        self.assertEqual(self.reopen().read(self.suite)["state"], "error")
        with self.assertRaises(LedgerError):
            self.reopen().resolve(self.suite, self.rows[0]["execution_id"])
        with self.assertRaises(LedgerError):
            self.reopen().prepare(self.suite, self.rows)
        self.reader.assert_called_once_with()

    def test_preparing_record_cannot_authorize_early_execution(self):
        def inspect():
            self.assertEqual(self.store.read(self.suite)["state"], "preparing")
            with self.assertRaises(LedgerError):
                self.store.resolve(self.suite, self.rows[0]["execution_id"])
            return self.snapshot
        self.reader.side_effect = inspect
        self.prepare()

    def test_expired_future_and_foreign_suite_are_rejected(self):
        self.prepare()
        with self.assertRaises(LedgerError):
            self.store.resolve(str(uuid4()), self.rows[0]["execution_id"])
        for now in (999, 1240):
            self.clock[0] = now
            with self.assertRaises(LedgerError):
                self.store.resolve(self.suite, self.rows[0]["execution_id"])

    def test_changed_case_contract_cannot_reuse_old_records(self):
        self.prepare()
        changed = run_tests.cases.cases()
        changed[1]["status"] = "IN_PROGRESS"
        restarted = module.SuiteStore(self.path, changed, self.reader, now=lambda: self.clock[0])
        with self.assertRaises(LedgerError):
            restarted.resolve(self.suite, self.rows[0]["execution_id"])

    def test_unknown_or_secret_resource_fields_are_not_saved(self):
        self.snapshot["aws_secret_access_key"] = "not-a-real-secret"
        with self.assertRaises(LedgerError):
            self.prepare()
        root = self.store.read(self.suite)
        self.assertIsNone(root["resources"])
        self.assertNotIn("not-a-real-secret", str(root))

    def test_contract_fixtures_do_not_construct_aws_clients(self):
        self.prepare()
        factory = Mock(side_effect=AssertionError("unexpected provider"))
        backend = module.RegisteredBackend(self.store, factory)
        for row in self.store.read(self.suite)["cases"]:
            if row["case_id"] == "job_status-error":
                with self.assertRaises(LedgerError):
                    backend.job_status(row["current_job_id"])
            else:
                self.assertEqual(backend.job_status(row["current_job_id"])["provider_mode"], "contract")
        factory.assert_not_called()

    def test_fixture_retrieval_before_completion_is_rejected(self):
        self.prepare()
        backend = module.RegisteredBackend(self.store, Mock())
        for row in self.store.read(self.suite)["cases"]:
            if row["case_id"] not in {"current-complete", "contract-complete"}:
                with self.assertRaises(LedgerError):
                    backend.retrieve(row["current_job_id"])

    def test_binding_change_blocks_native_factory(self):
        binding = module.Binding("native-current", "JOB1234567", "KB12345678", "DS12345678",
                                 "s3://p03-fixture/h03/knowledge/")
        self.snapshot = {"provider_mode": "aws", "binding": asdict(binding),
                         "source_uris": [binding.source_uri_prefix + "current-policy.md"]}
        self.prepare()
        factory = Mock()
        backend = module.RegisteredBackend(self.store, factory)
        self.snapshot["binding"]["provider_ingestion_job_id"] = "OTHER12345"
        job = self.store.resolve(self.suite, self.rows[0]["execution_id"])
        with self.assertRaises(LedgerError):
            backend.job_status(job)
        factory.assert_not_called()


class NativeAdapterTests(unittest.TestCase):
    setUp = backend_tests.BackendTests.setUp
    queue_status = backend_tests.BackendTests.queue_status
    queue_retrieval = backend_tests.BackendTests.queue_retrieval

    def test_registered_alias_preserves_native_ids_and_actual_sdk_arguments(self):
        with TemporaryDirectory() as directory:
            snapshot = {"provider_mode": "aws", "binding": asdict(self.binding),
                        "source_uris": [self.binding.source_uri_prefix + "current-policy.md"]}
            store = module.SuiteStore(Path(directory) / "state.sqlite3", run_tests.cases.cases(), lambda: deepcopy(snapshot))
            suite = str(uuid4())
            rows = [{"case_id": case["case_id"], "execution_id": str(uuid4())} for case in run_tests.cases.cases()]
            store.prepare(suite, rows)
            alias = store.resolve(suite, rows[0]["execution_id"])
            backend = module.RegisteredBackend(store, module.bedrock_factory(store, self.agent, self.runtime))
            self.queue_status()
            self.queue_retrieval()
            result = backend.retrieve(alias)
            self.assertEqual(result["ingestion_job_id"], alias)
            self.assertNotEqual(alias, self.binding.current_job_id)
            self.assertEqual(result["provider_ingestion_job_id"], self.binding.provider_ingestion_job_id)
            self.assertEqual(result["results"], self.result["retrievalResults"])
            snapshot["binding"]["data_source_id"] = "OTHER12345"
            with self.assertRaises(LedgerError):
                backend.retrieve(alias)


if __name__ == "__main__":
    unittest.main()
