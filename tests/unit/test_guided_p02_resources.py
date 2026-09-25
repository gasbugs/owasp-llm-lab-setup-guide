"""Read-only AWS connection checks using SDK doubles, not actual AWS resources."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway"
with patch.dict(sys.modules):
    for name in ("p02_ledger", "p02_resources"):
        spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
        value = importlib.util.module_from_spec(spec)
        sys.modules[name] = value
        spec.loader.exec_module(value)
    module = sys.modules["p02_resources"]
    ledger = sys.modules["p02_ledger"]


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.state = {"status": "READY", "provider_mode": "aws", "region": "us-east-1", "source_prefix": "h02/knowledge/",
                      "embedding_model_id": "amazon.titan-embed-text-v2:0", "dimensions": 1024, "account_id": "000000000000",
                      "template_digest": "a" * 64, "source_bucket": "source", "vector_bucket": "vectors",
                      "index_arn": "index", "knowledge_base_id": "kb", "data_source_id": "ds"}
        self.s3, self.agent, self.vectors = Mock(), Mock(), Mock()
        self.factory = Mock(side_effect=lambda name: {"s3": self.s3, "bedrock-agent": self.agent, "s3vectors": self.vectors}[name])
        self.s3.head_bucket.return_value = {"ResponseMetadata": {"RequestId": "head"}}
        self.kb = {"knowledgeBaseId": "kb", "status": "ACTIVE",
                   "knowledgeBaseConfiguration": {"type": "VECTOR", "vectorKnowledgeBaseConfiguration": {
                       "embeddingModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v2:0",
                       "embeddingModelConfiguration": {"bedrockEmbeddingModelConfiguration": {"dimensions": 1024, "embeddingDataType": "FLOAT32"}}}},
                   "storageConfiguration": {"type": "S3_VECTORS", "s3VectorsConfiguration": {"indexArn": "index"}}}
        self.ds = {"knowledgeBaseId": "kb", "dataSourceId": "ds", "status": "AVAILABLE",
                   "dataSourceConfiguration": {"type": "S3", "s3Configuration": {"bucketArn": "arn:aws:s3:::source",
                        "bucketOwnerAccountId": "000000000000", "inclusionPrefixes": ["h02/knowledge/"]}}}
        self.index = {"indexArn": "index", "dimension": 1024, "dataType": "float32", "distanceMetric": "cosine"}
        self.agent.get_knowledge_base.return_value = {"knowledgeBase": self.kb, "ResponseMetadata": {"RequestId": "kb-get"}}
        self.agent.get_data_source.return_value = {"dataSource": self.ds, "ResponseMetadata": {"RequestId": "ds-get"}}
        self.vectors.get_index.return_value = {"index": self.index, "ResponseMetadata": {"RequestId": "index-get"}}

    def check(self):
        return module.connection_evidence(self.state, client_factory=self.factory, mode="aws")

    def test_native_configuration_is_requeried_without_create_or_repair(self):
        result = self.check()
        self.assertTrue(result["connection_verified"])
        self.assertEqual(result["resource_request_ids"], ["head", "kb-get", "ds-get", "index-get"])
        self.s3.head_bucket.assert_called_once_with(Bucket="source", ExpectedBucketOwner="000000000000")
        self.agent.get_data_source.assert_called_once_with(knowledgeBaseId="kb", dataSourceId="ds")
        self.vectors.get_index.assert_called_once_with(indexArn="index")
        self.assertEqual({call[0] for call in self.agent.mock_calls}, {"get_knowledge_base", "get_data_source"})

    def test_wrong_source_prefix_is_not_ready_even_if_saved_state_is_ready(self):
        self.ds["dataSourceConfiguration"]["s3Configuration"]["inclusionPrefixes"] = ["other/"]
        with self.assertRaises(ledger.LedgerError):
            self.check()

    def test_wrong_embedding_model_and_index_shape_are_rejected(self):
        original = deepcopy(self.kb)
        self.kb["knowledgeBaseConfiguration"]["vectorKnowledgeBaseConfiguration"]["embeddingModelArn"] = "different"
        with self.assertRaises(ledger.LedgerError):
            self.check()
        self.kb.clear()
        self.kb.update(original)
        self.index["dimension"] = 512
        with self.assertRaises(ledger.LedgerError):
            self.check()

    def test_sdk_failure_missing_ids_and_inactive_resource_are_errors(self):
        self.kb["status"] = "DELETING"
        with self.assertRaises(ledger.LedgerError):
            self.check()
        self.kb["status"] = "ACTIVE"
        self.s3.head_bucket.return_value = {}
        with self.assertRaises(ledger.LedgerError):
            self.check()
        self.s3.head_bucket.side_effect = RuntimeError("private detail")
        with self.assertRaises(ledger.LedgerError) as caught:
            self.check()
        self.assertNotIn("private", str(caught.exception))

    def test_explicit_contract_mode_never_constructs_aws_clients(self):
        self.state["provider_mode"] = "contract"
        result = module.connection_evidence(self.state, client_factory=self.factory, mode="contract")
        self.assertEqual(result["provider_mode"], "contract")
        self.assertTrue(result["resource_request_ids"][0].startswith("contract-"))
        self.factory.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
