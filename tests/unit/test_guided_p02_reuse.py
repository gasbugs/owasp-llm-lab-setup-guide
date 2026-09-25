"""SDK-double tests: existing resources must never be repaired implicitly."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
import test_guided_p02_resources as resource_tests

PATH = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway/p02_reuse.py"
spec = importlib.util.spec_from_file_location("p02_reuse_test", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReuseTests(unittest.TestCase):
    def setUp(self):
        self.template = {"account_id": "000000000000", "source_bucket": "source",
                         "role_name": "role", "role_arn": "arn:role",
                         "trust_policy": {"Statement": ["trust"]},
                         "runtime_policy": {"Statement": ["runtime"]}}
        self.tags = [{"Key": key, "Value": value} for key, value in module.TAGS.items()]
        self.s3, self.iam = Mock(), Mock()
        self.s3.get_bucket_tagging.return_value = {"TagSet": self.tags}
        self.s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": dict(module.PUBLIC_BLOCK)}
        self.role = {"Arn": "arn:role", "Tags": self.tags,
                     "AssumeRolePolicyDocument": self.template["trust_policy"]}
        self.iam.list_role_policies.return_value = {"PolicyNames": ["runtime"]}
        self.iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
        self.iam.get_role_policy.return_value = {"PolicyDocument": self.template["runtime_policy"]}

    def role_check(self):
        module.check_role(self.iam, self.template, self.role, "runtime")

    def test_matching_bucket_is_read_only_and_owner_bound(self):
        module.check_bucket(self.s3, self.template)
        for call in self.s3.mock_calls:
            self.assertTrue(call[0].startswith("get_"))
            self.assertEqual(call.kwargs["ExpectedBucketOwner"], "000000000000")

    def test_foreign_bucket_tags_rejected(self):
        self.s3.get_bucket_tagging.return_value = {"TagSet": []}
        with self.assertRaises(module.HTTPException) as caught:
            module.check_bucket(self.s3, self.template)
        self.assertEqual(caught.exception.status_code, 409)
        self.s3.put_bucket_tagging.assert_not_called()

    def test_public_bucket_not_repaired(self):
        self.s3.get_public_access_block.return_value["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] = False
        with self.assertRaises(module.HTTPException):
            module.check_bucket(self.s3, self.template)
        self.s3.put_public_access_block.assert_not_called()

    def test_matching_role_uses_only_read_calls(self):
        self.role_check()
        self.assertEqual([call[0] for call in self.iam.mock_calls],
                         ["list_role_policies", "list_attached_role_policies", "get_role_policy"])

    def test_role_identity_trust_tags_and_boundary_rejected(self):
        for key, value in (("Arn", "foreign"), ("AssumeRolePolicyDocument", {}),
                           ("Tags", []), ("PermissionsBoundary", {})):
            with self.subTest(key=key):
                original = dict(self.role)
                self.role[key] = value
                with self.assertRaises(module.HTTPException):
                    self.role_check()
                self.role = original
        self.iam.update_assume_role_policy.assert_not_called()

    def test_extra_or_paginated_policies_rejected(self):
        for response in ({"PolicyNames": ["runtime", "other"]},
                         {"PolicyNames": ["runtime"], "IsTruncated": True},
                         {"PolicyNames": []}):
            with self.subTest(response=response):
                self.iam.list_role_policies.return_value = response
                with self.assertRaises(module.HTTPException):
                    self.role_check()

    def test_attached_policy_not_removed(self):
        self.iam.list_attached_role_policies.return_value = {"AttachedPolicies": [{"PolicyArn": "foreign"}]}
        with self.assertRaises(module.HTTPException):
            self.role_check()
        self.iam.detach_role_policy.assert_not_called()

    def test_runtime_policy_not_overwritten(self):
        self.iam.get_role_policy.return_value = {"PolicyDocument": {}}
        with self.assertRaises(module.HTTPException):
            self.role_check()
        self.iam.put_role_policy.assert_not_called()


class PreflightTests(unittest.TestCase):
    def setUp(self):
        reuse = ReuseTests()
        reuse.setUp()
        fixture = resource_tests.ResourceTests()
        fixture.setUp()
        self.s3, self.iam = reuse.s3, reuse.iam
        self.agent, self.vectors = fixture.agent, fixture.vectors
        self.template = {**fixture.state, **reuse.template, "vector_bucket_arn": "vector-arn",
                         "knowledge_base_name": "kb-name", "data_source_name": "ds-name"}
        self.s3.head_bucket.return_value = {"ResponseMetadata": {"RequestId": "head"}}
        self.vectors.get_vector_bucket.return_value = {"vectorBucket": {"vectorBucketArn": "vector-arn"}}
        self.iam.get_role.return_value = {"Role": reuse.role}
        self.agent.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": [{"name": "kb-name", "knowledgeBaseId": "kb"}]}
        self.agent.list_data_sources.return_value = {"dataSourceSummaries": [{"name": "ds-name", "dataSourceId": "ds"}]}
        self.agent.list_tags_for_resource.return_value = {"tags": module.TAGS}
        fixture.kb.update(name="kb-name", roleArn="arn:role", knowledgeBaseArn="arn:kb")
        fixture.ds.update(name="ds-name", dataDeletionPolicy="DELETE", vectorIngestionConfiguration={
            "chunkingConfiguration": {"chunkingStrategy": "FIXED_SIZE", "fixedSizeChunkingConfiguration": {
                "maxTokens": 200, "overlapPercentage": 20}}})
        self.fixture = fixture
        self.addCleanup(self.read_only)

    def read_only(self):
        for client in (self.s3, self.iam, self.agent, self.vectors):
            for call in client.mock_calls:
                self.assertTrue(call[0].startswith(("get_", "list_", "head_")), call)

    def check(self):
        with patch.dict("sys.modules", {"p02_resources": resource_tests.module,
                                        "p02_ledger": resource_tests.ledger}):
            return module.preflight(self.template, s3=self.s3, vectors=self.vectors,
                                    iam=self.iam, agent=self.agent, policy_name="runtime")

    def absent(self):
        self.s3.head_bucket.side_effect = ClientError({"Error": {"Code": "404"}}, "HeadBucket")
        self.vectors.get_vector_bucket.side_effect = ClientError({"Error": {"Code": "NotFoundException"}}, "GetVectorBucket")
        self.iam.get_role.side_effect = ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetRole")
        self.agent.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": []}

    def test_all_absent_allows_create(self):
        self.absent()
        self.assertIsNone(self.check())

    def test_complete_set_reuses_native_connection_evidence(self):
        result = self.check()
        self.assertEqual(result["knowledge_base_id"], "kb")
        self.assertEqual(result["aws_request_ids"], ["head", "kb-get", "ds-get", "index-get"])
        self.agent.list_tags_for_resource.assert_called_once_with(resourceArn="arn:kb")

    def test_tag_request_matches_installed_sdk_shape(self):
        from botocore.session import Session
        from botocore.validate import validate_parameters
        self.fixture.kb["knowledgeBaseArn"] = "arn:aws:bedrock:us-east-1:000000000000:knowledge-base/ABCDEFGHIJ"
        self.check()
        operation = Session().get_service_model("bedrock-agent").operation_model("ListTagsForResource")
        validate_parameters(self.agent.list_tags_for_resource.call_args.kwargs, operation.input_shape)

    def test_partial_set_rejected(self):
        self.absent()
        self.s3.head_bucket.side_effect = None
        with self.assertRaises(module.HTTPException):
            self.check()

    def test_forbidden_is_not_absent(self):
        self.s3.head_bucket.side_effect = ClientError({"Error": {"Code": "403"}}, "HeadBucket")
        with self.assertRaises(ClientError):
            self.check()

    def test_later_page_existing_kb_prevents_create(self):
        self.absent()
        self.agent.list_knowledge_bases.side_effect = [
            {"knowledgeBaseSummaries": [], "nextToken": "page2"},
            {"knowledgeBaseSummaries": [{"name": "kb-name", "knowledgeBaseId": "kb"}]}]
        with self.assertRaises(module.HTTPException):
            self.check()
        self.assertEqual(self.agent.list_knowledge_bases.call_args.kwargs["nextToken"], "page2")

    def test_repeated_pagination_token_rejected(self):
        self.agent.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": [], "nextToken": "same"}
        with self.assertRaises(module.HTTPException):
            self.check()
        self.assertEqual(self.agent.list_knowledge_bases.call_count, 2)

    def test_other_data_source_on_later_page_rejected(self):
        self.agent.list_data_sources.side_effect = [
            {"dataSourceSummaries": [{"name": "ds-name", "dataSourceId": "ds"}], "nextToken": "page2"},
            {"dataSourceSummaries": [{"name": "foreign", "dataSourceId": "other"}]}]
        with self.assertRaises(module.HTTPException):
            self.check()

    def test_wrong_chunking_rejected(self):
        self.fixture.ds["vectorIngestionConfiguration"] = {}
        with self.assertRaises(module.HTTPException):
            self.check()

    def test_wrong_embedding_rejected_by_native_checker(self):
        self.fixture.kb["knowledgeBaseConfiguration"]["vectorKnowledgeBaseConfiguration"]["embeddingModelArn"] = "foreign"
        with self.assertRaises(module.HTTPException) as caught:
            self.check()
        self.assertEqual(caught.exception.status_code, 502)


if __name__ == "__main__":
    unittest.main()
