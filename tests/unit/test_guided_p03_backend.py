"""Pinned SDK request/response model tests, without AWS/network access."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

import boto3
from botocore.stub import Stubber

PATH = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway/p03_backend.py"
spec = importlib.util.spec_from_file_location("p03_backend_under_test", PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.binding = module.Binding("h03-current", "JOB1234567", "KB12345678", "DS12345678",
                                      "s3://p03-fixture/h03/knowledge/")
        self.current = Mock(return_value=self.binding)
        self.agent, self.runtime = [boto3.client(
            name, region_name="us-east-1", aws_access_key_id="fixture", aws_secret_access_key="fixture")
            for name in ("bedrock-agent", "bedrock-agent-runtime")]
        self.agent_stub, self.runtime_stub = Stubber(self.agent), Stubber(self.runtime)
        for stub in (self.agent_stub, self.runtime_stub):
            stub.activate()
            self.addCleanup(stub.deactivate)
            self.addCleanup(stub.assert_no_pending_responses)
        self.backend = module.BedrockSearchBackend(self.binding, self.current, self.agent, self.runtime)
        self.status = {"ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "status-request"},
                       "ingestionJob": {"ingestionJobId": "JOB1234567", "knowledgeBaseId": "KB12345678",
                                        "dataSourceId": "DS12345678", "status": "COMPLETE",
                                        "startedAt": datetime.now(timezone.utc),
                                        "updatedAt": datetime.now(timezone.utc),
                                        "statistics": {"numberOfDocumentsFailed": 0}}}
        self.result = {"ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "retrieve-request"},
                       "retrievalResults": [{"location": {"type": "S3", "s3Location": {
                           "uri": self.binding.source_uri_prefix + "current-policy.md"}},
                           "content": {"type": "TEXT", "text": "Current synthetic policy"},
                           "score": 0.7, "metadata": {"x-amz-bedrock-kb-chunk-id": "chunk-1"}}]}

    def queue_status(self, response=None):
        self.agent_stub.add_response("get_ingestion_job", response or self.status, {
            "knowledgeBaseId": "KB12345678", "dataSourceId": "DS12345678", "ingestionJobId": "JOB1234567"})

    def queue_retrieval(self, response=None):
        self.runtime_stub.add_response("retrieve", response or self.result, {
            "knowledgeBaseId": "KB12345678", "retrievalQuery": {"text": self.backend.QUERY},
            "retrievalConfiguration": {"vectorSearchConfiguration": {"numberOfResults": 3}}})

    def test_status_keeps_native_ids_and_issues_no_start_or_retrieval(self):
        self.queue_status()
        result = self.backend.job_status("h03-current")
        self.assertEqual(result["ingestion_job_id"], "h03-current")
        self.assertEqual(result["provider_ingestion_job_id"], "JOB1234567")
        self.assertEqual(result["provider_request_id"], "status-request")
        self.assertEqual(result["provider_mode"], "aws")

    def test_search_rechecks_current_native_job_and_preserves_results(self):
        self.queue_status()
        self.queue_retrieval()
        result = self.backend.retrieve("h03-current")
        self.assertEqual(result["results"], self.result["retrievalResults"])
        self.assertEqual(result["status_observation"]["provider_request_id"], "status-request")
        self.assertEqual(result["provider_request_id"], "retrieve-request")
        self.assertNotIn("task_completed", result)

    def test_pending_failed_and_stopped_jobs_never_search(self):
        for state in ("STARTING", "IN_PROGRESS", "FAILED", "STOPPING", "STOPPED"):
            with self.subTest(state=state):
                response = deepcopy(self.status)
                response["ingestionJob"]["status"] = state
                self.queue_status(response)
                with self.assertRaises(module.BackendError):
                    self.backend.retrieve("h03-current")

    def test_partial_ingestion_failure_never_searches(self):
        self.status["ingestionJob"]["statistics"]["numberOfDocumentsFailed"] = 1
        self.queue_status()
        with self.assertRaises(module.BackendError):
            self.backend.retrieve("h03-current")

    def test_missing_failure_statistics_does_not_mean_zero_failures(self):
        self.status["ingestionJob"]["statistics"] = {}
        self.queue_status()
        with self.assertRaises(module.BackendError):
            self.backend.retrieve("h03-current")

    def test_wrong_native_identifiers_are_rejected(self):
        for key in ("ingestionJobId", "knowledgeBaseId", "dataSourceId"):
            response = deepcopy(self.status)
            response["ingestionJob"][key] = "FOREIGN123"
            self.queue_status(response)
            with self.assertRaises(module.BackendError):
                self.backend.job_status("h03-current")

    def test_wrong_current_job_is_rejected_before_sdk(self):
        with self.assertRaises(module.BackendError):
            self.backend.job_status("h03-previous")
        self.current.return_value = replace(self.binding, knowledge_base_id="OTHER12345")
        with self.assertRaises(module.BackendError):
            self.backend.retrieve("h03-current")

    def test_changed_binding_after_status_is_not_accepted(self):
        self.current.side_effect = [self.binding, replace(self.binding, current_job_id="h03-new")]
        self.queue_status()
        with self.assertRaises(module.BackendError):
            self.backend.retrieve("h03-current")

    def test_changed_binding_after_retrieval_is_not_accepted(self):
        self.current.side_effect = [self.binding] * 3 + [replace(self.binding, current_job_id="h03-new")]
        self.queue_status()
        self.queue_retrieval()
        with self.assertRaises(module.BackendError):
            self.backend.retrieve("h03-current")

    def test_missing_request_id_is_not_invented(self):
        del self.status["ResponseMetadata"]["RequestId"]
        self.queue_status()
        with self.assertRaises(module.BackendError):
            self.backend.job_status("h03-current")

    def test_foreign_source_is_not_returned(self):
        self.result["retrievalResults"][0]["location"]["s3Location"]["uri"] = "s3://p02-fixture/h02/knowledge/document.md"
        self.queue_status()
        self.queue_retrieval()
        with self.assertRaises(module.BackendError):
            self.backend.retrieve("h03-current")

    def test_native_sdk_errors_are_not_converted_to_ready(self):
        self.agent_stub.add_client_error("get_ingestion_job", service_error_code="ResourceNotFoundException")
        with self.assertRaises(self.agent.exceptions.ResourceNotFoundException):
            self.backend.retrieve("h03-current")

    def test_incomplete_or_reused_retrieval_evidence_is_rejected(self):
        for change in ({"nextToken": "next-page"}, {"ResponseMetadata": {
                "HTTPStatusCode": 200, "RequestId": "status-request"}}):
            response = {**deepcopy(self.result), **change}
            self.queue_status()
            self.queue_retrieval(response)
            with self.assertRaises(module.BackendError):
                self.backend.retrieve("h03-current")

    def test_wrong_region_or_namespace_is_rejected(self):
        for changes in ({"region": "us-west-2"}, {"source_uri_prefix": "s3://p02-fixture/h02/knowledge/"},
                        {"provider_ingestion_job_id": ""}):
            with self.assertRaises(module.BackendError):
                replace(self.binding, **changes)

    def test_adapter_output_survives_registered_provider_ledger(self):
        from tempfile import TemporaryDirectory
        from uuid import uuid4
        from test_guided_p03_api import ledger_module, provider_module

        with TemporaryDirectory() as directory:
            ledger = ledger_module.SearchLedger(Path(directory) / "evidence.sqlite3")
            suite, execution = str(uuid4()), str(uuid4())
            grant = ledger.register(suite, execution, "a" * 64, "b" * 64, "h03-current")
            provider = provider_module.SearchProvider(ledger, self.backend)
            self.queue_status()
            provider.invoke(grant["capability"], suite, execution, "job_status", {})
            recheck = deepcopy(self.status)
            recheck["ResponseMetadata"]["RequestId"] = "status-recheck-request"
            self.queue_status(recheck)
            self.queue_retrieval()
            result = provider.invoke(grant["capability"], suite, execution, "retrieve", {})
            ledger.close(execution)
            receipt = ledger.read(execution)
            self.assertTrue(receipt["closed"])
            self.assertEqual([call["state"] for call in receipt["calls"]], ["complete", "complete"])
            self.assertEqual(receipt["calls"][1]["response"], result)
            self.assertEqual(result["status_observation"]["provider_request_id"], "status-recheck-request")
            self.assertNotIn("task_completed", receipt)

    def test_premature_search_is_recorded_as_error_not_zero_calls(self):
        from tempfile import TemporaryDirectory
        from uuid import uuid4
        from test_guided_p03_api import ledger_module, provider_module

        with TemporaryDirectory() as directory:
            ledger = ledger_module.SearchLedger(Path(directory) / "evidence.sqlite3")
            suite, execution = str(uuid4()), str(uuid4())
            grant = ledger.register(suite, execution, "a" * 64, "b" * 64, "h03-current")
            provider = provider_module.SearchProvider(ledger, self.backend)
            self.status["ingestionJob"]["status"] = "IN_PROGRESS"
            self.queue_status()
            with self.assertRaises(ledger_module.LedgerError):
                provider.invoke(grant["capability"], suite, execution, "retrieve", {})
            ledger.close(execution)
            receipt = ledger.read(execution)
            self.assertTrue(receipt["closed"])
            self.assertEqual(len(receipt["calls"]), 1)
            self.assertEqual(receipt["calls"][0]["state"], "error")
            self.assertIsNone(receipt["calls"][0]["response"])


if __name__ == "__main__":
    unittest.main()
