"""Coordinator wiring tests; AWS operations are substituted explicitly."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway"
with patch.object(sys, "path", [str(ROOT), *sys.path]):
    spec = importlib.util.spec_from_file_location("p03_aws_preparation_test", ROOT / "p03_aws_preparation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "state.sqlite3"
        self.operation = str(uuid4())
        self.account = "000000000000"
        self.factory = Mock(return_value={name: Mock() for name in ("sts", "s3", "vectors", "iam", "agent")})
        prefix = "s3://owasp-guided-p03-000000000000-source/h03/knowledge/"
        self.snapshot = {"provider_mode": "aws", "binding": {"current_job_id": "p03-" + self.operation.replace("-", ""),
            "provider_ingestion_job_id": "JOB1234567", "knowledge_base_id": "KB12345678", "data_source_id": "DS12345678",
            "source_uri_prefix": prefix, "region": "us-east-1"}, "source_uris": [prefix + "current-policy.md"]}
        self.resources = self.enterContext(patch.object(module, "prepare_resources", return_value={"resource_action": "created"}))
        self.document = self.enterContext(patch.object(module, "prepare_document", return_value={
            "snapshot": self.snapshot, "evidence": {"preparation_request_ids": ["native-1"]}}))

    def run_prepare(self):
        return module.prepare_aws(self.path, self.operation, self.account, client_factory=self.factory)

    def test_full_callback_publishes_snapshot_and_evidence(self):
        result = self.run_prepare()
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["resources"], self.snapshot)
        self.assertEqual(result["evidence"]["document"]["preparation_request_ids"], ["native-1"])
        self.assertEqual(module.PreparationStore(self.path).read(self.operation), result)
        self.factory.assert_called_once_with("us-east-1")
        self.document.assert_called_once()
        self.assertEqual(self.document.call_args.args[1], self.resources.return_value)

    def test_resource_error_prevents_document_work(self):
        self.resources.side_effect = RuntimeError("private-text")
        with self.assertRaises(module.LedgerError):
            self.run_prepare()
        self.document.assert_not_called()
        result = module.PreparationStore(self.path).read(self.operation)
        self.assertEqual(result["state"], "error")
        self.assertIsNone(result["evidence"])
        self.assertNotIn("private-text", str(result))

    def test_document_error_never_publishes_ready(self):
        self.document.side_effect = RuntimeError("failed ingestion")
        with self.assertRaises(module.LedgerError):
            self.run_prepare()
        with self.assertRaises(module.LedgerError):
            module.PreparationStore(self.path).resources()

    def test_repeated_operation_does_not_construct_sdk(self):
        self.run_prepare()
        self.factory.reset_mock()
        with self.assertRaises(module.LedgerError):
            self.run_prepare()
        self.factory.assert_not_called()

    def test_invalid_snapshot_does_not_publish_evidence(self):
        bad = deepcopy(self.snapshot)
        bad["source_uris"] = []
        self.document.return_value["snapshot"] = bad
        with self.assertRaises(module.LedgerError):
            self.run_prepare()
        self.assertIsNone(module.PreparationStore(self.path).read(self.operation)["evidence"])

    def test_sdk_factory_has_bounded_single_attempt_settings(self):
        with patch.object(module.boto3, "client", return_value=Mock()) as factory:
            module.clients("us-east-1")
        self.assertEqual(factory.call_count, 5)
        for call in factory.call_args_list:
            config = call.kwargs["config"]
            self.assertEqual(config.retries["total_max_attempts"], 1)
            self.assertEqual((config.connect_timeout, config.read_timeout), (5, 20))
            self.assertEqual(call.kwargs["region_name"], "us-east-1")


if __name__ == "__main__":
    unittest.main()
