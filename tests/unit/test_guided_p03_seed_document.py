"""Source/ingestion SDK doubles; never a live AWS completion claim."""
from copy import deepcopy
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from botocore.exceptions import ClientError, ConnectionClosedError
from botocore.session import Session
from botocore.validate import validate_parameters

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway"
with patch.object(sys, "path", [str(ROOT), *sys.path]):
    spec = importlib.util.spec_from_file_location("p03_seed_document_test", ROOT / "p03_seed_document.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


class DocumentTests(unittest.TestCase):
    def setUp(self):
        self.t = module.template("000000000000")
        self.connection = {key: self.t[key] for key in ("account_id", "region", "template_digest")}
        self.connection.update(knowledge_base_id="KB12345678", data_source_id="DS12345678")
        self.operation = str(uuid4())
        self.s3, self.agent, self.sleep = Mock(), Mock(), Mock()
        self.listing = {"IsTruncated": False, "Contents": [{"Key": "h03/knowledge/current-policy.md"}]}
        self.job = {"knowledgeBaseId": "KB12345678", "dataSourceId": "DS12345678", "ingestionJobId": "JOB1234567",
                    "status": "COMPLETE", "statistics": {"numberOfDocumentsFailed": 0}}
        self.serial = 0
        self.bodies = []
        self.s3.list_objects_v2.side_effect = lambda **kw: self.response(self.listing)
        self.s3.get_object.side_effect = self.object_response
        self.s3.put_object.side_effect = lambda **kw: self.response({})
        self.agent.start_ingestion_job.side_effect = lambda **kw: self.response({"ingestionJob": self.job})
        self.agent.get_ingestion_job.side_effect = lambda **kw: self.response({"ingestionJob": self.job})
        self.addCleanup(self.check_boundaries)

    def response(self, body):
        self.serial += 1
        return {**deepcopy(body), "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "native-" + str(self.serial)}}

    def object_response(self, **kw):
        body = io.BytesIO(module.DOCUMENT)
        self.bodies.append(body)
        return {**self.response({"ContentLength": len(module.DOCUMENT)}), "Body": body}

    def prepare(self):
        return module.prepare_document(self.t, self.connection, self.operation,
                                       s3=self.s3, agent=self.agent, sleep=self.sleep)

    def check_boundaries(self):
        self.assertTrue(all(body.closed for body in self.bodies))
        for client in (self.s3, self.agent):
            for call in client.mock_calls:
                self.assertFalse(call[0].startswith(("delete_", "retrieve", "converse", "stop_")))

    def test_existing_document_is_not_overwritten(self):
        result = self.prepare()
        self.s3.put_object.assert_not_called()
        self.assertEqual(result["evidence"]["source_action"], "reused")
        self.assertEqual(result["snapshot"]["binding"]["current_job_id"], "p03-" + self.operation.replace("-", ""))
        self.assertEqual(len(result["evidence"]["preparation_request_ids"]), 6)

    def test_new_document_uses_conditional_write(self):
        self.s3.list_objects_v2.side_effect = [self.response({"IsTruncated": False}), self.response(self.listing)]
        result = self.prepare()
        self.assertEqual(result["evidence"]["source_action"], "created")
        self.assertEqual(self.s3.put_object.call_args.kwargs["IfNoneMatch"], "*")
        self.assertEqual(self.s3.put_object.call_args.kwargs["Body"], module.DOCUMENT)
        session = Session()
        for client, service in ((self.s3, "s3"), (self.agent, "bedrock-agent")):
            model = session.get_service_model(service)
            for call in client.mock_calls:
                operation = "".join(part.title() for part in call[0].split("_"))
                validate_parameters(call.kwargs, model.operation_model(operation).input_shape)

    def test_conflicting_write_does_not_start_job(self):
        self.s3.list_objects_v2.side_effect = [self.response({"IsTruncated": False})]
        self.s3.put_object.side_effect = ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
        with self.assertRaises(module.LedgerError):
            self.prepare()
        self.agent.start_ingestion_job.assert_not_called()

    def test_foreign_prefix_content_not_deleted_or_ingested(self):
        self.listing["Contents"].append({"Key": "h03/knowledge/foreign.md"})
        with self.assertRaises(module.LedgerError):
            self.prepare()
        self.s3.put_object.assert_not_called()
        self.agent.start_ingestion_job.assert_not_called()

    def test_different_bytes_rejected_and_stream_closed(self):
        body = io.BytesIO(b"x" * len(module.DOCUMENT))
        self.bodies.append(body)
        self.s3.get_object.side_effect = [{**self.response({"ContentLength": len(module.DOCUMENT)}), "Body": body}]
        with self.assertRaises(module.LedgerError):
            self.prepare()
        self.agent.start_ingestion_job.assert_not_called()

    def test_missing_failed_count_not_assumed_zero(self):
        self.job["statistics"] = {}
        with self.assertRaises(module.LedgerError):
            self.prepare()

    def test_bool_failed_count_rejected(self):
        self.job["statistics"]["numberOfDocumentsFailed"] = False
        with self.assertRaises(module.LedgerError):
            self.prepare()

    def test_failed_job_not_published(self):
        self.job["status"] = "FAILED"
        with self.assertRaises(module.LedgerError):
            self.prepare()

    def test_changed_job_id_rejected(self):
        changed = deepcopy(self.job)
        changed["ingestionJobId"] = "JOB7654321"
        self.agent.get_ingestion_job.side_effect = [self.response({"ingestionJob": changed})]
        with self.assertRaises(module.LedgerError):
            self.prepare()

    def test_current_job_polled_without_start_retry(self):
        pending = deepcopy(self.job)
        pending["status"] = "IN_PROGRESS"
        self.agent.get_ingestion_job.side_effect = [self.response({"ingestionJob": pending}), self.response({"ingestionJob": self.job})]
        self.prepare()
        self.assertEqual(self.agent.start_ingestion_job.call_count, 1)
        self.sleep.assert_called_once_with(2)

    def test_closed_final_listing_retried_once_without_repeating_ingestion(self):
        self.s3.list_objects_v2.side_effect = [
            self.response(self.listing), ConnectionClosedError(endpoint_url="https://s3.test"),
            self.response(self.listing)]
        result = self.prepare()
        self.assertEqual(result["evidence"]["status"], "COMPLETE")
        self.assertEqual(self.s3.list_objects_v2.call_count, 3)
        self.assertEqual(self.agent.start_ingestion_job.call_count, 1)
        self.s3.put_object.assert_not_called()
        self.sleep.assert_not_called()

    def test_repeated_closed_listing_stays_error(self):
        self.s3.list_objects_v2.side_effect = ConnectionClosedError(endpoint_url="https://s3.test")
        with self.assertRaises(module.LedgerError):
            self.prepare()
        self.assertEqual(self.s3.list_objects_v2.call_count, 2)
        self.agent.start_ingestion_job.assert_not_called()

    def test_closed_listing_does_not_retry_past_deadline(self):
        clock = [0]
        def disconnected(**kwargs):
            clock[0] = 181
            raise ConnectionClosedError(endpoint_url="https://s3.test")
        self.s3.list_objects_v2.side_effect = disconnected
        with self.assertRaises(module.LedgerError):
            module.prepare_document(self.t, self.connection, self.operation,
                                    s3=self.s3, agent=self.agent, monotonic=lambda: clock[0])
        self.assertEqual(self.s3.list_objects_v2.call_count, 1)
        self.agent.start_ingestion_job.assert_not_called()

    def test_access_denied_listing_not_retried(self):
        self.s3.list_objects_v2.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "ListObjectsV2")
        with self.assertRaises(module.LedgerError):
            self.prepare()
        self.assertEqual(self.s3.list_objects_v2.call_count, 1)
        self.agent.start_ingestion_job.assert_not_called()

    def test_connection_closed_on_write_not_retried(self):
        self.s3.list_objects_v2.side_effect = [self.response({"IsTruncated": False})]
        self.s3.put_object.side_effect = ConnectionClosedError(endpoint_url="https://s3.test")
        with self.assertRaises(module.LedgerError):
            self.prepare()
        self.assertEqual(self.s3.put_object.call_count, 1)
        self.agent.start_ingestion_job.assert_not_called()

    def test_connection_closed_on_start_ingestion_not_retried(self):
        self.agent.start_ingestion_job.side_effect = ConnectionClosedError(endpoint_url="https://agent.test")
        with self.assertRaises(module.LedgerError):
            self.prepare()
        self.assertEqual(self.agent.start_ingestion_job.call_count, 1)
        self.agent.get_ingestion_job.assert_not_called()

    def test_pending_is_bounded(self):
        self.job["status"] = "IN_PROGRESS"
        with self.assertRaises(module.LedgerError):
            self.prepare()
        self.assertEqual(self.agent.get_ingestion_job.call_count, 60)

    def test_changed_source_after_job_rejected(self):
        self.s3.list_objects_v2.side_effect = [self.response(self.listing), self.response({"IsTruncated": False})]
        with self.assertRaises(module.LedgerError):
            self.prepare()

    def test_foreign_connection_before_any_call(self):
        self.connection["account_id"] = "111111111111"
        with self.assertRaises(module.LedgerError):
            self.prepare()
        self.assertFalse(self.s3.mock_calls or self.agent.mock_calls)

    def test_error_log_identifies_operation_without_exception_message(self):
        self.s3.list_objects_v2.__name__ = "list_objects_v2"
        self.s3.list_objects_v2.side_effect = TimeoutError("private-provider-detail")
        with self.assertLogs(module.__name__, level="WARNING") as logs:
            with self.assertRaises(module.LedgerError) as raised:
                self.prepare()
        self.assertEqual(raised.exception.status, 502)
        self.assertIn("operation=list_objects_v2 type=TimeoutError", logs.output[0])
        self.assertNotIn("private-provider-detail", " ".join(logs.output))
        self.agent.start_ingestion_job.assert_not_called()


if __name__ == "__main__":
    unittest.main()
