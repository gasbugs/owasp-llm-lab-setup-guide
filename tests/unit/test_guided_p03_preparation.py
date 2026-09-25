"""Preparation transaction tests; no AWS or network calls."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway"
with patch.object(sys, "path", [str(ROOT), *sys.path]):
    spec = importlib.util.spec_from_file_location("p03_preparation_test", ROOT / "p03_preparation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "gateway.sqlite3"
        self.now = Mock(return_value=1000.0)
        self.store = module.PreparationStore(self.path, now=self.now)
        self.operation = str(uuid4())
        self.account = "000000000000"
        self.prefix = "s3://owasp-guided-p03-000000000000-source/h03/knowledge/"
        self.snapshot = {"provider_mode": "aws", "binding": {
            "current_job_id": "p03-" + self.operation.replace("-", ""),
            "provider_ingestion_job_id": "JOB1234567", "knowledge_base_id": "KB12345678",
            "data_source_id": "DS12345678", "source_uri_prefix": self.prefix, "region": "us-east-1"},
            "source_uris": [self.prefix + "current-policy.md"]}

    def test_success_publishes_atomically_and_survives_restart(self):
        callback = Mock(return_value=self.snapshot)
        self.assertEqual(self.store.run(self.operation, self.account, callback), self.snapshot)
        self.assertEqual(module.PreparationStore(self.path).resources(), self.snapshot)
        callback.assert_called_once_with(module.template(self.account), self.operation)

    def test_interrupted_operation_remains_locked_after_restart(self):
        self.store.begin(self.operation, self.account)
        restarted = module.PreparationStore(self.path)
        with self.assertRaises(module.LedgerError):
            restarted.begin(str(uuid4()), self.account)
        with self.assertRaises(module.LedgerError):
            restarted.resources()

    def test_failure_does_not_publish_or_serialize_exception(self):
        callback = Mock(side_effect=RuntimeError("credential-like-private-text"))
        with self.assertRaises(module.LedgerError) as caught:
            self.store.run(self.operation, self.account, callback)
        self.assertEqual(caught.exception.status, 502)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT state FROM p03_preparations").fetchone()[0], "error")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM resource_state").fetchone()[0], 0)
            self.assertNotIn("credential-like-private-text", "\n".join(db.iterdump()))

    def test_previous_success_does_not_mask_new_failure(self):
        self.store.run(self.operation, self.account, Mock(return_value=self.snapshot))
        second = str(uuid4())
        self.store.begin(second, self.account)
        with self.assertRaises(module.LedgerError):
            self.store.resources()
        self.store.fail(second)
        with self.assertRaises(module.LedgerError):
            self.store.resources()

    def test_duplicate_operation_never_calls_callback(self):
        self.store.run(self.operation, self.account, Mock(return_value=self.snapshot))
        callback = Mock()
        with self.assertRaises(module.LedgerError):
            self.store.run(self.operation, self.account, callback)
        callback.assert_not_called()

    def test_concurrent_prepare_does_not_enter_second_callback(self):
        entered, release = threading.Event(), threading.Event()
        outcomes = []

        def prepare(specification, operation):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test callback timeout")
            return self.snapshot

        def run():
            try:
                outcomes.append(self.store.run(self.operation, self.account, prepare))
            except Exception as error:
                outcomes.append(error)

        worker = threading.Thread(target=run)
        worker.start()
        try:
            self.assertTrue(entered.wait(5))
            callback = Mock()
            with self.assertRaises(module.LedgerError):
                module.PreparationStore(self.path).run(str(uuid4()), self.account, callback)
            callback.assert_not_called()
        finally:
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcomes, [self.snapshot])

    def test_closed_preparation_cannot_be_overwritten(self):
        self.store.run(self.operation, self.account, Mock(return_value=self.snapshot))
        with self.assertRaises(module.LedgerError):
            self.store.publish(self.operation, self.snapshot)
        with self.assertRaises(module.LedgerError):
            self.store.fail(self.operation)
        self.assertEqual(self.store.resources(), self.snapshot)

    def test_other_problem_rows_preserved(self):
        with sqlite3.connect(self.path) as db:
            db.executemany("INSERT INTO resource_state VALUES(?,?)", [(name, "untouched") for name in ("h03", "h02", "p02", "h11")])
        self.store.run(self.operation, self.account, Mock(return_value=self.snapshot))
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM resource_state WHERE state_json='untouched'").fetchone()[0], 4)

    def test_foreign_account_requires_operator_resolution(self):
        self.store.begin(self.operation, self.account)
        self.store.fail(self.operation)
        with self.assertRaises(module.LedgerError):
            self.store.begin(str(uuid4()), "111111111111")

    def test_invalid_id_before_callback(self):
        callback = Mock()
        with self.assertRaises(module.LedgerError):
            self.store.run("invalid", self.account, callback)
        callback.assert_not_called()

    def test_foreign_prefix_job_region_or_source_not_published(self):
        variants = []
        for field, value in (("source_uri_prefix", "s3://foreign/h03/knowledge/"),
                             ("current_job_id", "p03-foreign"), ("region", "us-west-2")):
            candidate = deepcopy(self.snapshot)
            candidate["binding"][field] = value
            variants.append(candidate)
        candidate = deepcopy(self.snapshot)
        candidate["source_uris"] = [self.prefix + "other.md"]
        variants.append(candidate)
        self.store.begin(self.operation, self.account)
        for candidate in variants:
            with self.subTest(candidate=candidate), self.assertRaises(module.LedgerError):
                self.store.publish(self.operation, candidate)
        with self.assertRaises(module.LedgerError):
            self.store.resources()

    def test_deadline_and_clock_rollback_do_not_publish(self):
        self.store.begin(self.operation, self.account)
        for value in (999, 1901, float("nan")):
            self.now.return_value = value
            with self.subTest(value=value), self.assertRaises(module.LedgerError):
                self.store.publish(self.operation, self.snapshot)

    def test_stored_binding_change_is_not_ready(self):
        self.store.run(self.operation, self.account, Mock(return_value=self.snapshot))
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE resource_state SET state_json='{}' WHERE logical_name='p03'")
        with self.assertRaises(module.LedgerError):
            self.store.resources()


if __name__ == "__main__":
    unittest.main()
