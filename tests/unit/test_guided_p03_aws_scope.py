"""Publisher preflight guards only; no AWS/network calls."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[2]
with patch.object(sys, "path", [str(ROOT / "llm-security-control-plane/guided-bedrock-gateway"), *sys.path]):
    from p03_ledger import LedgerError
    spec = importlib.util.spec_from_file_location("publisher_p03_scope", ROOT / "tests/e2e/p03_aws_scope.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.sdk = {key: Mock() for key in ("sts", "s3", "vectors", "iam", "agent")}
        self.sdk["sts"].get_caller_identity.return_value = {"Account": "000000000000",
            "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "sts-id"}}
        self.sdk["agent"].list_knowledge_bases.return_value = {"knowledgeBaseSummaries": [],
            "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "kb-list-id"}}
        for key, method, code in (("s3", "head_bucket", "404"),
                                  ("vectors", "get_vector_bucket", "NotFoundException"),
                                  ("iam", "get_role", "NoSuchEntity")):
            getattr(self.sdk[key], method).side_effect = ClientError({"Error": {"Code": code}}, method)
        self.factory = Mock(return_value=self.sdk)

    def run_check(self, **kwargs):
        return module.preflight("000000000000", client_factory=self.factory, **kwargs)

    def test_absence_uses_production_audit_and_exact_names(self):
        result = self.run_check(now=lambda: 100)
        self.assertTrue(result["resources_absent"])
        self.assertEqual(result["template_digest"], module.template("000000000000")["template_digest"])
        self.assertTrue(all(name.startswith("owasp-guided-p03-") for name in result["names"].values()))
        self.sdk["s3"].head_bucket.assert_called_once_with(
            Bucket=result["names"]["source_bucket"], ExpectedBucketOwner="000000000000")
        for client in self.sdk.values():
            self.assertEqual(client.meta.events.register.call_count, 2)

    def test_invalid_account_rejected_before_client_creation(self):
        with self.assertRaises(ValueError):
            module.preflight("invalid", client_factory=self.factory)
        self.factory.assert_not_called()

    def test_wrong_account_rejected_before_resource_reads(self):
        self.sdk["sts"].get_caller_identity.return_value["Account"] = "111111111111"
        with self.assertRaises(LedgerError):
            self.run_check()
        self.sdk["s3"].head_bucket.assert_not_called()

    def test_missing_identity_evidence_rejected(self):
        self.sdk["sts"].get_caller_identity.return_value["ResponseMetadata"] = {}
        with self.assertRaises(LedgerError):
            self.run_check()
        self.sdk["s3"].head_bucket.assert_not_called()

    def test_partial_resources_are_not_repaired_or_adopted(self):
        self.sdk["s3"].head_bucket.side_effect = None
        self.sdk["s3"].head_bucket.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "source-id"}}
        with self.assertRaises(LedgerError):
            self.run_check()
        self.sdk["s3"].create_bucket.assert_not_called()

    def test_complete_existing_resources_not_adopted(self):
        with patch.object(module, "inspect_existing", return_value={"knowledge_base_id": "KB12345678"}):
            with self.assertRaisesRegex(ValueError, "not publisher-owned"):
                self.run_check()

    def test_access_denied_is_not_absence(self):
        self.sdk["s3"].head_bucket.side_effect = ClientError({"Error": {"Code": "403"}}, "HeadBucket")
        with self.assertRaises(LedgerError):
            self.run_check()

    def test_long_or_backward_clock_observation_not_fresh(self):
        for end in (99, 400):
            with self.subTest(end=end), self.assertRaises(LedgerError):
                self.run_check(now=Mock(side_effect=[100, end]))

    def test_event_guard_rejects_writes_before_transmission(self):
        guard = module.ReadOnlyCalls()
        for name in ("PutObject", "CreateKnowledgeBase", "StartIngestionJob", "DeleteBucket", "InvokeModel"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                guard.before(SimpleNamespace(name=name))
        self.assertEqual(guard.attempted, [])
        for name in sorted(module.READ_OPERATIONS):
            guard.before(SimpleNamespace(name=name))
        self.assertEqual(set(guard.attempted), module.READ_OPERATIONS)

    def test_response_evidence_does_not_copy_bodies_or_error_messages(self):
        guard = module.ReadOnlyCalls()
        guard.after(SimpleNamespace(name="HeadBucket"), {
            "secret": "do-not-copy", "Error": {"Code": "404", "Message": "do-not-copy"},
            "ResponseMetadata": {"HTTPStatusCode": 404, "RequestId": "request-id", "HTTPHeaders": {"secret": "do-not-copy"}}})
        self.assertEqual(guard.responses, [{"operation": "HeadBucket", "status": 404,
                                          "request_id": "request-id", "error_code": "404"}])


if __name__ == "__main__":
    unittest.main()
