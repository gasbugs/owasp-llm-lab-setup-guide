"""Cleanup scope tests with SDK doubles, not permission to delete live resources."""
from copy import deepcopy
import importlib.util
from io import BytesIO
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from botocore.exceptions import ClientError
from botocore.session import Session
from botocore.validate import validate_parameters

ROOT = Path(__file__).resolve().parents[2]
with patch.object(sys, "path", [str(ROOT / "llm-security-control-plane/guided-bedrock-gateway"),
                                str(ROOT / "tests/e2e"), *sys.path]):
    from p03_ledger import LedgerError
    spec = importlib.util.spec_from_file_location("publisher_p03_cleanup", ROOT / "tests/e2e/p03_aws_cleanup.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.account = "000000000000"
        self.t = t = module.template(self.account)
        self.before = {"account_id": self.account, "region": t["region"], "resources_absent": True,
            "preflight_id": str(uuid4()), "template_digest": t["template_digest"], "started_at": 100,
            "finished_at": 110, "names": {key: t[key] for key in
            ("source_bucket", "vector_bucket", "role_name", "knowledge_base_name")}}
        operation = uuid4()
        connection = {key: t[key] for key in ("account_id", "region", "template_digest")}
        connection.update(resource_action="created", knowledge_base_id="KB12345678", data_source_id="DS12345678")
        prefix = "s3://" + t["source_bucket"] + "/" + t["source_prefix"]
        self.prepared = {"practice_id": "P03", "state": "ready", "operation_id": str(operation),
            "account_id": self.account, "template_digest": t["template_digest"], "started_at": 120, "finished_at": 140,
            "evidence": {"connection": connection, "document": {"source_action": "created",
                "source_sha256": module.DOCUMENT_SHA, "status": "COMPLETE", "number_of_documents_failed": 0,
                "provider_ingestion_job_id": "JOB1234567"}},
            "resources": {"provider_mode": "aws", "binding": {"current_job_id": "p03-" + operation.hex,
                "provider_ingestion_job_id": "JOB1234567", "knowledge_base_id": "KB12345678",
                "data_source_id": "DS12345678", "region": t["region"], "source_uri_prefix": prefix},
                "source_uris": [prefix + "current-policy.md"]}}
        self.sdk = {key: Mock() for key in ("sts", "s3", "vectors", "iam", "agent")}
        self.sdk["sts"].get_caller_identity.return_value = {"Account": self.account}
        self.sdk["s3"].get_bucket_versioning.return_value = {}
        self.sdk["s3"].list_objects_v2.return_value = {"IsTruncated": False,
            "Contents": [{"Key": t["source_prefix"] + "current-policy.md"}]}
        self.body = BytesIO(module.DOCUMENT)
        self.sdk["s3"].get_object.return_value = {"ContentLength": len(module.DOCUMENT), "Body": self.body}
        self.sdk["agent"].list_ingestion_jobs.return_value = {"ingestionJobSummaries": [
            {"ingestionJobId": "JOB1234567", "status": "COMPLETE"}]}
        self.sdk["agent"].get_ingestion_job.return_value = {"ingestionJob": {
            "knowledgeBaseId": "KB12345678", "dataSourceId": "DS12345678", "ingestionJobId": "JOB1234567",
            "status": "COMPLETE", "statistics": {"numberOfDocumentsFailed": 0}}}
        for name in ("get_data_source", "get_knowledge_base"):
            getattr(self.sdk["agent"], name).side_effect = ClientError(
                {"Error": {"Code": "ResourceNotFoundException"}}, name)
        self.store = Mock()
        self.store.read.return_value = deepcopy(self.prepared)
        self.store.resources.return_value = deepcopy(self.prepared["resources"])
        for name, value in (("PreparationStore", self.store), ("inspect_existing", deepcopy(connection)),
                            ("preflight", {"resources_absent": True})):
            patcher = patch.object(module, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.factory = Mock(return_value=self.sdk)

    def run_cleanup(self):
        return module.cleanup_created(self.account, self.before, self.prepared, "unused",
                                      client_factory=self.factory, now=lambda: 150, sleep=lambda _: None)

    def deletes(self):
        return [(key, call) for key, client in self.sdk.items() for call in client.mock_calls
                if call[0].startswith("delete_")]

    def test_exact_successful_scope_and_sdk_delete_shapes(self):
        self.assertTrue(self.run_cleanup()["resources_absent"])
        self.assertEqual(len(self.deletes()), 8)
        self.assertTrue(self.body.closed)
        session = Session()
        for key, call in self.deletes():
            service = {"agent": "bedrock-agent", "vectors": "s3vectors"}.get(key, key)
            operation = "".join(part.title() for part in call[0].split("_"))
            shape = session.get_service_model(service).operation_model(operation).input_shape
            validate_parameters(call.kwargs, shape)

    def test_stale_or_wrong_preflight_stops_before_sdk(self):
        for key, value in (("account_id", "111111111111"), ("resources_absent", False),
                           ("started_at", -4000), ("finished_at", 130), ("template_digest", "foreign")):
            original = deepcopy(self.before)
            self.before[key] = value
            with self.subTest(key=key), self.assertRaises(LedgerError):
                self.run_cleanup()
            self.before = original
        self.factory.assert_not_called()

    def test_reused_resources_are_never_deleted(self):
        self.prepared["evidence"]["connection"]["resource_action"] = "reused"
        with self.assertRaises(LedgerError):
            self.run_cleanup()
        self.factory.assert_not_called()

    def test_changed_local_journal_stops_before_sdk(self):
        self.store.read.return_value["state"] = "error"
        with self.assertRaises(LedgerError):
            self.run_cleanup()
        self.factory.assert_not_called()

    def test_configuration_audit_failure_prevents_all_deletes(self):
        module.inspect_existing.side_effect = LedgerError(409)
        with self.assertRaises(LedgerError):
            self.run_cleanup()
        self.assertEqual(self.deletes(), [])

    def test_other_source_object_prevents_all_deletes(self):
        self.sdk["s3"].list_objects_v2.return_value["Contents"].append({"Key": "other-file"})
        with self.assertRaises(LedgerError):
            self.run_cleanup()
        self.assertEqual(self.deletes(), [])

    def test_versioned_bucket_prevents_all_deletes(self):
        self.sdk["s3"].get_bucket_versioning.return_value = {"Status": "Enabled"}
        with self.assertRaises(LedgerError):
            self.run_cleanup()
        self.assertEqual(self.deletes(), [])

    def test_changed_source_closes_stream_and_prevents_deletes(self):
        self.body = BytesIO(b"changed")
        self.sdk["s3"].get_object.return_value["Body"] = self.body
        with self.assertRaises(LedgerError):
            self.run_cleanup()
        self.assertTrue(self.body.closed)
        self.assertEqual(self.deletes(), [])

    def test_other_job_or_page_prevents_deletes(self):
        self.sdk["agent"].list_ingestion_jobs.return_value["nextToken"] = "more-jobs"
        with self.assertRaises(LedgerError):
            self.run_cleanup()
        self.assertEqual(self.deletes(), [])

    def test_running_job_prevents_deletes(self):
        self.sdk["agent"].get_ingestion_job.return_value["ingestionJob"]["status"] = "IN_PROGRESS"
        with self.assertRaises(LedgerError):
            self.run_cleanup()
        self.assertEqual(self.deletes(), [])

    def test_delete_permission_error_stops_remaining_steps(self):
        self.sdk["agent"].get_data_source.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "GetDataSource")
        with self.assertRaises(ClientError):
            self.run_cleanup()
        self.assertEqual(len(self.deletes()), 1)

    def test_deletion_poll_is_bounded_and_not_treated_as_success(self):
        self.sdk["agent"].get_data_source.side_effect = None
        with self.assertRaises(TimeoutError):
            self.run_cleanup()
        self.assertEqual(self.sdk["agent"].get_data_source.call_count, 60)
        self.assertEqual(len(self.deletes()), 1)


if __name__ == "__main__":
    unittest.main()
