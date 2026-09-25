"""Creation SDK request contracts, without real cloud calls or provisioning."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from botocore.exceptions import ClientError
from botocore.session import Session
from botocore.validate import validate_parameters

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway"
with patch.object(sys, "path", [str(ROOT), *sys.path]):
    spec = importlib.util.spec_from_file_location("p03_create_resources_test", ROOT / "p03_create_resources.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


class CreationTests(unittest.TestCase):
    def setUp(self):
        self.t = t = module.template("000000000000")
        self.operation = str(uuid4())
        self.clients = {name: Mock() for name in ("sts", "s3", "vectors", "iam", "agent")}
        self.responses = {}
        self.response("sts", "get_caller_identity", {"Account": t["account_id"]})
        for method in ("create_bucket", "put_public_access_block", "put_bucket_tagging"):
            self.response("s3", method, {})
        self.response("vectors", "create_vector_bucket", {"vectorBucketArn": t["vector_bucket_arn"]})
        self.response("vectors", "create_index", {"indexArn": t["index_arn"]})
        self.response("iam", "create_role", {"Role": {"Arn": t["role_arn"]}})
        self.response("iam", "put_role_policy", {})
        kb = {"knowledgeBaseId": "KB12345678", "name": t["knowledge_base_name"], "roleArn": t["role_arn"], "status": "ACTIVE"}
        ds = {"dataSourceId": "DS12345678", "knowledgeBaseId": "KB12345678", "name": t["data_source_name"], "status": "AVAILABLE"}
        for method in ("create_knowledge_base", "get_knowledge_base"):
            self.response("agent", method, {"knowledgeBase": kb})
        for method in ("create_data_source", "get_data_source"):
            self.response("agent", method, {"dataSource": ds})
        self.audit_result = {"account_id": t["account_id"], "region": t["region"],
                             "template_digest": t["template_digest"], "knowledge_base_id": "KB12345678",
                             "data_source_id": "DS12345678", "resource_request_ids": ["audit"]}
        self.audit = self.enterContext(patch.object(module, "inspect_existing", side_effect=[None, self.audit_result]))
        self.sleep = Mock()
        self.clock = Mock(return_value=1000)
        self.addCleanup(self.no_destructive_calls)

    def response(self, name, method, body):
        value = deepcopy(body)
        value["ResponseMetadata"] = {"HTTPStatusCode": 200, "RequestId": name + "-" + method}
        self.responses[method] = value
        getattr(self.clients[name], method).return_value = value

    def run_prepare(self):
        return module.prepare_resources(self.t, self.operation, **self.clients, sleep=self.sleep, monotonic=self.clock)

    def no_destructive_calls(self):
        for client in self.clients.values():
            for call in client.mock_calls:
                self.assertFalse(call[0].startswith(("delete_", "update_", "start_ingestion", "put_object")))

    def test_create_then_audit(self):
        result = self.run_prepare()
        self.assertEqual(result["resource_action"], "created")
        self.assertEqual(len(result["preparation_request_ids"]), 12)
        self.assertEqual(self.audit.call_count, 2)
        self.assertEqual(result["knowledge_base_id"], "KB12345678")

    def test_every_request_matches_pinned_sdk(self):
        self.run_prepare()
        session = Session()
        for name, service in (("sts", "sts"), ("s3", "s3"), ("vectors", "s3vectors"),
                              ("iam", "iam"), ("agent", "bedrock-agent")):
            model = session.get_service_model(service)
            for call in self.clients[name].mock_calls:
                operation = "".join(part.title() for part in call[0].split("_"))
                validate_parameters(call.kwargs, model.operation_model(operation).input_shape)

    def test_reuse_is_read_only(self):
        self.audit.side_effect = [self.audit_result]
        self.assertEqual(self.run_prepare()["resource_action"], "reused")
        for name in ("s3", "vectors", "iam", "agent"):
            self.assertEqual(self.clients[name].mock_calls, [])
        self.sleep.assert_not_called()

    def test_account_mismatch_stops_before_audit(self):
        self.responses["get_caller_identity"]["Account"] = "111111111111"
        with self.assertRaises(module.LedgerError):
            self.run_prepare()
        self.audit.assert_not_called()
        self.clients["s3"].create_bucket.assert_not_called()

    def test_partial_or_foreign_state_never_repaired(self):
        self.audit.side_effect = module.LedgerError(409)
        with self.assertRaises(module.LedgerError):
            self.run_prepare()
        self.clients["s3"].create_bucket.assert_not_called()

    def test_failed_create_stops_without_retry_or_cleanup(self):
        self.clients["agent"].create_knowledge_base.side_effect = ClientError(
            {"Error": {"Code": "ValidationException", "Message": "private error"}}, "CreateKnowledgeBase")
        with self.assertRaises(module.LedgerError) as caught:
            self.run_prepare()
        self.assertEqual(caught.exception.status, 502)
        self.assertNotIn("private error", str(caught.exception))
        self.assertEqual(self.clients["agent"].create_knowledge_base.call_count, 1)
        self.clients["agent"].create_data_source.assert_not_called()

    def test_terminal_status_prevents_data_source_creation(self):
        self.responses["get_knowledge_base"]["knowledgeBase"]["status"] = "FAILED"
        with self.assertRaises(module.LedgerError):
            self.run_prepare()
        self.clients["agent"].create_data_source.assert_not_called()

    def role_delay(self):
        return ClientError({"Error": {"Code": "ValidationException", "Message":
            "Bedrock Knowledge Base was unable to assume the given role. "
            "Provide the proper permissions and retry the request."}}, "CreateKnowledgeBase")

    def test_role_propagation_reuses_identical_idempotent_request(self):
        method = self.clients["agent"].create_knowledge_base
        method.side_effect = [self.role_delay(), self.role_delay(), self.responses["create_knowledge_base"]]
        self.assertEqual(self.run_prepare()["resource_action"], "created")
        self.assertEqual(method.call_count, 3)
        self.assertTrue(all(call == method.call_args_list[0] for call in method.call_args_list))
        self.clients["iam"].create_role.assert_called_once()
        self.clients["vectors"].create_index.assert_called_once()

    def test_role_propagation_retry_has_six_attempt_limit(self):
        self.clients["agent"].create_knowledge_base.side_effect = self.role_delay()
        with self.assertRaises(module.LedgerError):
            self.run_prepare()
        self.assertEqual(self.clients["agent"].create_knowledge_base.call_count, 6)
        self.assertEqual(self.sleep.call_count, 6)
        self.clients["agent"].create_data_source.assert_not_called()

    def test_role_message_under_different_code_is_not_retried(self):
        error = self.role_delay()
        error.response["Error"]["Code"] = "AccessDeniedException"
        self.clients["agent"].create_knowledge_base.side_effect = error
        with self.assertRaises(module.LedgerError):
            self.run_prepare()
        self.assertEqual(self.clients["agent"].create_knowledge_base.call_count, 1)

    def test_wrong_created_vector_arn_stops(self):
        self.responses["create_vector_bucket"]["vectorBucketArn"] = "foreign"
        with self.assertRaises(module.LedgerError):
            self.run_prepare()
        self.clients["vectors"].create_index.assert_not_called()

    def test_post_creation_audit_failure_not_success(self):
        self.audit.side_effect = [None, module.LedgerError(409)]
        with self.assertRaises(module.LedgerError):
            self.run_prepare()

    def test_deadline_stops_before_call(self):
        self.clock.side_effect = [1000, 1241]
        with self.assertRaises(module.LedgerError):
            self.run_prepare()
        self.clients["sts"].get_caller_identity.assert_not_called()

    def test_pending_is_polled_without_duplicate_create(self):
        first = deepcopy(self.responses["get_knowledge_base"])
        first["knowledgeBase"]["status"] = "CREATING"
        first["ResponseMetadata"]["RequestId"] = "first-poll"
        self.clients["agent"].get_knowledge_base.side_effect = [first, self.responses["get_knowledge_base"]]
        self.run_prepare()
        self.assertEqual(self.clients["agent"].create_knowledge_base.call_count, 1)
        self.assertEqual(self.clients["agent"].get_knowledge_base.call_count, 2)
        self.sleep.assert_any_call(2)

    def test_pending_poll_count_is_bounded(self):
        pages = []
        for number in range(60):
            response = deepcopy(self.responses["get_knowledge_base"])
            response["knowledgeBase"]["status"] = "CREATING"
            response["ResponseMetadata"]["RequestId"] = "poll-" + str(number)
            pages.append(response)
        self.clients["agent"].get_knowledge_base.side_effect = pages
        with self.assertRaises(module.LedgerError):
            self.run_prepare()
        self.assertEqual(self.clients["agent"].get_knowledge_base.call_count, 60)
        self.clients["agent"].create_data_source.assert_not_called()

    def test_final_audit_must_match_created_ids(self):
        self.audit_result["knowledge_base_id"] = "KB87654321"
        with self.assertRaises(module.LedgerError):
            self.run_prepare()

    def test_returned_kb_identity_is_checked_before_next_write(self):
        self.responses["get_knowledge_base"]["knowledgeBase"]["knowledgeBaseId"] = "KB87654321"
        with self.assertRaises(module.LedgerError):
            self.run_prepare()
        self.clients["agent"].create_data_source.assert_not_called()


if __name__ == "__main__":
    unittest.main()
