"""Read-only SDK doubles; these checks are not live AWS provisioning evidence."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from botocore.session import Session
from botocore.validate import validate_parameters

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway"
with patch.object(sys, "path", [str(ROOT), *sys.path]):
    spec = importlib.util.spec_from_file_location("p03_resource_contract_test", ROOT / "p03_resource_contract.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


class ResourceContractTests(unittest.TestCase):
    def setUp(self):
        self.t = t = module.template("000000000000")
        self.clients = {name: Mock() for name in ("s3", "vectors", "iam", "agent")}
        self.responses = {}
        tags = [{"Key": key, "Value": value} for key, value in t["tags"].items()]
        self.response("s3", "head_bucket", {})
        self.response("s3", "get_bucket_tagging", {"TagSet": tags})
        self.response("s3", "get_public_access_block", {"PublicAccessBlockConfiguration": t["public_access_block"]})
        self.response("vectors", "get_vector_bucket", {"vectorBucket": {"vectorBucketArn": t["vector_bucket_arn"]}})
        self.response("vectors", "get_index", {"index": {"indexArn": t["index_arn"], "dimension": 1024,
                                                       "dataType": "float32", "distanceMetric": "cosine"}})
        self.response("iam", "get_role", {"Role": {"Arn": t["role_arn"], "Tags": tags,
                                                   "AssumeRolePolicyDocument": t["trust_policy"]}})
        self.response("iam", "list_role_policies", {"PolicyNames": [t["policy_name"]], "IsTruncated": False})
        self.response("iam", "list_attached_role_policies", {"AttachedPolicies": [], "IsTruncated": False})
        self.response("iam", "get_role_policy", {"PolicyDocument": t["runtime_policy"]})
        self.response("agent", "list_knowledge_bases", {"knowledgeBaseSummaries": [
            {"name": t["knowledge_base_name"], "knowledgeBaseId": "KB12345678"}]})
        self.response("agent", "get_knowledge_base", {"knowledgeBase": {
            "knowledgeBaseId": "KB12345678", "knowledgeBaseArn": "arn:aws:bedrock:us-east-1:000000000000:knowledge-base/KB12345678",
            "status": "ACTIVE", "name": t["knowledge_base_name"], "roleArn": t["role_arn"],
            "knowledgeBaseConfiguration": t["knowledge_base_configuration"], "storageConfiguration": t["storage_configuration"]}})
        self.response("agent", "list_tags_for_resource", {"tags": t["tags"]})
        self.response("agent", "list_data_sources", {"dataSourceSummaries": [
            {"name": t["data_source_name"], "dataSourceId": "DS12345678"}]})
        self.response("agent", "get_data_source", {"dataSource": {
            "knowledgeBaseId": "KB12345678", "dataSourceId": "DS12345678", "status": "AVAILABLE",
            "name": t["data_source_name"], "dataDeletionPolicy": "DELETE",
            "dataSourceConfiguration": t["data_source_configuration"], "vectorIngestionConfiguration": t["ingestion_configuration"]}})
        self.addCleanup(self.assert_read_only, self.clients)

    def response(self, client, method, body):
        result = deepcopy(body)
        result["ResponseMetadata"] = {"HTTPStatusCode": 200, "RequestId": client + "-" + method}
        self.responses[method] = result
        getattr(self.clients[client], method).return_value = result

    def check(self):
        return module.inspect_existing(self.t, **self.clients)

    def assert_read_only(self, clients):
        for client in clients.values():
            for call in client.mock_calls:
                self.assertTrue(call[0].startswith(("get_", "head_", "list_")), call)

    def rejects(self, status=409):
        with self.assertRaises(module.LedgerError) as caught:
            self.check()
        self.assertEqual(caught.exception.status, status)

    def absent(self):
        for client, method, code in (("s3", "head_bucket", "404"),
                                     ("vectors", "get_vector_bucket", "NotFoundException"),
                                     ("iam", "get_role", "NoSuchEntity")):
            getattr(self.clients[client], method).side_effect = ClientError({"Error": {"Code": code}}, method)
        self.responses["list_knowledge_bases"]["knowledgeBaseSummaries"] = []

    def test_complete_set_is_reused_with_native_read_ids(self):
        result = self.check()
        self.assertEqual(result["knowledge_base_id"], "KB12345678")
        self.assertEqual(result["data_source_id"], "DS12345678")
        self.assertEqual(len(result["resource_request_ids"]), 14)
        self.assertEqual(result["template_digest"], self.t["template_digest"])
        for call in self.clients["s3"].mock_calls:
            self.assertEqual(call.kwargs["ExpectedBucketOwner"], self.t["account_id"])

    def test_all_sdk_request_shapes(self):
        self.check()
        session = Session()
        for name, service in (("s3", "s3"), ("vectors", "s3vectors"), ("iam", "iam"), ("agent", "bedrock-agent")):
            model = session.get_service_model(service)
            for call in self.clients[name].mock_calls:
                operation = "".join(part.title() for part in call[0].split("_"))
                validate_parameters(call.kwargs, model.operation_model(operation).input_shape)

    def test_absent_set_does_not_write(self):
        self.absent()
        self.assertIsNone(self.check())

    def test_partial_set_does_not_repair(self):
        self.absent()
        self.clients["s3"].head_bucket.side_effect = None
        self.rejects()

    def test_forbidden_is_not_absent(self):
        self.clients["s3"].head_bucket.side_effect = ClientError({"Error": {"Code": "403"}}, "HeadBucket")
        self.rejects(502)

    def test_foreign_activity_tags_rejected(self):
        for activity in ("H03", "H02", "P02"):
            with self.subTest(activity=activity):
                self.setUp()
                self.responses["list_tags_for_resource"]["tags"]["Activity"] = activity
                self.rejects()

    def test_role_configuration_drift_rejected(self):
        for field, value in (("Arn", "foreign"), ("Tags", []),
                             ("AssumeRolePolicyDocument", {}), ("PermissionsBoundary", {})):
            with self.subTest(field=field):
                self.setUp()
                self.responses["get_role"]["Role"][field] = value
                self.rejects()

    def test_runtime_policy_drift_rejected(self):
        self.responses["get_role_policy"]["PolicyDocument"]["Statement"][0]["Resource"] = "*"
        self.rejects()

    def test_extra_attached_policy_rejected(self):
        self.responses["list_attached_role_policies"]["AttachedPolicies"] = [{"PolicyArn": "foreign"}]
        self.rejects()

    def test_incomplete_policy_listing_rejected(self):
        for method in ("list_role_policies", "list_attached_role_policies"):
            with self.subTest(method=method):
                self.setUp()
                self.responses[method]["IsTruncated"] = True
                self.rejects()

    def test_ownership_and_connection_mismatches_rejected(self):
        changes = [("get_bucket_tagging", None, "TagSet", []),
                   ("get_vector_bucket", "vectorBucket", "vectorBucketArn", "foreign"),
                   ("get_knowledge_base", "knowledgeBase", "knowledgeBaseArn", "foreign"),
                   ("get_knowledge_base", "knowledgeBase", "roleArn", "foreign"),
                   ("get_data_source", "dataSource", "knowledgeBaseId", "KB87654321"),
                   ("get_data_source", "dataSource", "dataSourceId", "DS87654321")]
        for method, section, key, value in changes:
            with self.subTest(method=method, key=key):
                self.setUp()
                target = self.responses[method] if section is None else self.responses[method][section]
                target[key] = value
                self.rejects()

    def test_configuration_drift_rejected(self):
        changes = [("get_public_access_block", "PublicAccessBlockConfiguration", "BlockPublicPolicy", False),
                   ("get_index", "index", "dimension", 512),
                   ("get_knowledge_base", "knowledgeBase", "status", "CREATING"),
                   ("get_knowledge_base", "knowledgeBase", "storageConfiguration", {}),
                   ("get_data_source", "dataSource", "vectorIngestionConfiguration", {}),
                   ("get_data_source", "dataSource", "dataSourceConfiguration", {})]
        for method, section, key, value in changes:
            with self.subTest(method=method, key=key):
                self.setUp()
                self.responses[method][section][key] = value
                self.rejects()

    def test_untrusted_template_rejected_before_sdk(self):
        self.t["source_bucket"] = "foreign"
        self.rejects()
        self.assertFalse(any(client.mock_calls for client in self.clients.values()))

    def test_missing_or_duplicate_request_ids_rejected(self):
        self.responses["get_index"]["ResponseMetadata"]["RequestId"] = "s3-head_bucket"
        self.rejects()
        self.responses["get_index"]["ResponseMetadata"] = {}
        self.rejects(502)

    def test_duplicate_kb_names_rejected(self):
        rows = self.responses["list_knowledge_bases"]["knowledgeBaseSummaries"]
        rows.append(dict(rows[0], knowledgeBaseId="KB87654321"))
        self.rejects()

    def test_second_page_is_examined(self):
        first = deepcopy(self.responses["list_data_sources"])
        first["nextToken"] = "page2"
        second = {"dataSourceSummaries": [{"name": "foreign", "dataSourceId": "DS87654321"}],
                  "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "page2"}}
        self.clients["agent"].list_data_sources.side_effect = [first, second]
        self.rejects()
        self.assertEqual(self.clients["agent"].list_data_sources.call_args.kwargs["nextToken"], "page2")

    def test_malformed_pagination_not_treated_as_end(self):
        for token in (None, "", False, 0, [], {}):
            with self.subTest(token=token):
                self.responses["list_knowledge_bases"]["nextToken"] = token
                self.rejects()

    def test_repeated_token_stops(self):
        first = deepcopy(self.responses["list_knowledge_bases"])
        first["nextToken"] = "same"
        second = deepcopy(first)
        second["ResponseMetadata"]["RequestId"] = "second"
        self.clients["agent"].list_knowledge_bases.side_effect = [first, second]
        self.rejects()
        self.assertEqual(self.clients["agent"].list_knowledge_bases.call_count, 2)

    def test_pagination_is_bounded(self):
        pages = []
        for number in range(100):
            page = deepcopy(self.responses["list_knowledge_bases"])
            page["nextToken"] = str(number)
            page["ResponseMetadata"]["RequestId"] = "page-" + str(number)
            pages.append(page)
        self.clients["agent"].list_knowledge_bases.side_effect = pages
        self.rejects()
        self.assertEqual(self.clients["agent"].list_knowledge_bases.call_count, 100)

    def test_template_is_account_scoped_and_fresh(self):
        first = module.template("000000000000")
        second = module.template("111111111111")
        self.assertNotEqual(first["template_digest"], second["template_digest"])
        self.assertNotEqual(first["source_bucket"], second["source_bucket"])
        first["tags"]["Activity"] = "other"
        self.assertEqual(module.template("000000000000")["tags"]["Activity"], "P03")
        for account in (None, 123, "123", "０" * 12):
            with self.assertRaises(ValueError):
                module.template(account)
        with self.assertRaises(ValueError):
            module.template("000000000000", "us-west-2")


if __name__ == "__main__":
    unittest.main()
