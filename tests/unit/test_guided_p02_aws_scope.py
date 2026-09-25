"""Publisher AWS ownership guard; mocked APIs only, no cloud side effects."""
import importlib.util
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.template = {"source_bucket": "test-source", "vector_bucket": "test-vectors",
                         "role_name": "test-role", "knowledge_base_name": "test-kb", "template_digest": "a" * 64}
        fake_server = SimpleNamespace(h02_template=lambda account: self.template)
        spec = importlib.util.spec_from_file_location("publisher_p02_scope",
            Path(__file__).resolve().parents[1] / "e2e/p02_aws_scope.py")
        self.module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"server": fake_server}):
            spec.loader.exec_module(self.module)
        self.clients = {name: Mock() for name in ("sts", "s3", "s3vectors", "iam", "bedrock-agent")}
        self.clients["sts"].get_caller_identity.return_value = {"Account": "000000000000"}
        for name, method, code in (("s3", "head_bucket", "404"), ("s3vectors", "get_vector_bucket", "NotFoundException"),
                                   ("iam", "get_role", "NoSuchEntity")):
            getattr(self.clients[name], method).side_effect = ClientError({"Error": {"Code": code}}, method)
        self.clients["bedrock-agent"].get_paginator.return_value.paginate.return_value = [{"knowledgeBaseSummaries": []}]
        self.client_patch = patch.object(self.module.boto3, "client", side_effect=lambda name, **kwargs: self.clients[name])
        self.client_patch.start()
        self.addCleanup(self.client_patch.stop)
        self.payload = {"account_id": "000000000000"}

    def assert_no_writes(self):
        for client in self.clients.values():
            self.assertFalse(any(call[0].split(".")[-1].startswith(("delete", "put", "create", "update"))
                                 for call in client.mock_calls))

    def test_absence_is_explicit_and_read_only(self):
        result = self.module.run("preflight", self.payload)
        self.assertEqual(len(result["checks"]), 4)
        self.assertTrue(all(result["checks"].values()))
        self.assertEqual(result["template_digest"], "a" * 64)
        self.assert_no_writes()

    def test_wrong_account_stops_before_resource_queries(self):
        with self.assertRaises(ValueError):
            self.module.run("preflight", {"account_id": "111111111111"})
        self.clients["s3"].head_bucket.assert_not_called()
        self.assert_no_writes()

    def test_existing_bucket_prevents_provisioning(self):
        self.clients["s3"].head_bucket.side_effect = None
        with self.assertRaises(ValueError):
            self.module.run("preflight", self.payload)
        self.assert_no_writes()

    def test_access_denied_is_not_absence(self):
        self.clients["s3"].head_bucket.side_effect = ClientError({"Error": {"Code": "403"}}, "HeadBucket")
        with self.assertRaises(ClientError):
            self.module.run("preflight", self.payload)
        self.assert_no_writes()

    def test_later_page_existing_kb_is_not_missed(self):
        self.clients["bedrock-agent"].get_paginator.return_value.paginate.return_value = [
            {"knowledgeBaseSummaries": []}, {"knowledgeBaseSummaries": [{"name": "test-kb"}]}]
        with self.assertRaises(ValueError):
            self.module.run("preflight", self.payload)
        self.assert_no_writes()

    def test_cleanup_requires_fresh_complete_absence_record(self):
        for changes in ({"observed_at": time.time() - 4000}, {"checks": {}}, {"account_id": "111111111111"}):
            before = {"account_id": "000000000000", "observed_at": time.time(),
                      "checks": dict.fromkeys(("source_absent", "vector_absent", "role_absent", "kb_absent"), True)}
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                self.module.run("cleanup", {**self.payload, "preflight": {**before, **changes}, "state": {}})
            self.assert_no_writes()

    def test_reuse_guard_rejects_write_before_transmission_and_restores_client(self):
        original = self.module.boto3.client
        def provision(execution_id):
            client = self.module.boto3.client("s3")
            callback = client.meta.events.register.call_args.args[1]
            callback(model=SimpleNamespace(name="PutBucketTagging"))
        self.module.server.provision_h02_aws = provision
        with self.assertRaisesRegex(AssertionError, "attempted an AWS write"):
            self.module.read_only_reuse({}, self.module.Config())
        self.assertIs(self.module.boto3.client, original)
        self.clients["s3"].put_bucket_tagging.assert_not_called()

    def test_reuse_guard_compares_resource_identity_and_records_reads(self):
        previous = {"status": "READY", "source_bucket": "test-source", "execution_id": "old"}
        stored = {}
        def provision(execution_id):
            client = self.module.boto3.client("s3")
            callback = client.meta.events.register.call_args.args[1]
            for name in sorted(self.module.READ_OPERATIONS):
                callback(model=SimpleNamespace(name=name))
            stored.update(previous, execution_id=execution_id)
            return stored
        self.module.server.provision_h02_aws = provision
        self.module.server.load_h02_state = lambda: stored
        result = self.module.read_only_reuse(previous, self.module.Config())
        self.assertTrue(result["verified"])
        self.assertEqual(set(result["aws_operations"]), self.module.READ_OPERATIONS)


if __name__ == "__main__":
    unittest.main()
