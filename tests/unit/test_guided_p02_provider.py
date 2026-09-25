"""Strict SDK doubles verify arguments and evidence; these are not live AWS tests."""
import importlib.util
import io
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway"


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ledger_module = load("p02_ledger")
previous = sys.modules.get("p02_ledger")
sys.modules["p02_ledger"] = ledger_module
try:
    provider_module = load("p02_provider")
finally:
    if previous is None:
        del sys.modules["p02_ledger"]
    else:
        sys.modules["p02_ledger"] = previous


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = ledger_module.DocumentLedger(Path(self.temp.name) / "test.sqlite3")
        self.suite, self.execution = str(uuid4()), str(uuid4())
        self.token = self.store.register(self.suite, self.execution, "a" * 64, "b" * 64)["capability"]
        self.s3, self.runtime = Mock(), Mock()
        self.provider = provider_module.DocumentProvider(self.store, self.s3, self.runtime, "test-owned-bucket")
        self.s3.put_object.return_value = {"ResponseMetadata": {"RequestId": "s3-request"}}
        self.document = {"key": f"h02/knowledge/{self.execution}.md", "content": "# 안내\n\n합성 문서 본문입니다.\n"}

    def invoke(self, operation, payload):
        return self.provider.invoke(self.token, self.suite, self.execution, operation, payload)

    def embedding_response(self, **updates):
        body = {"embedding": [1.0] + [0.0] * 1023, "inputTextTokenCount": 8, **updates}
        self.stream = io.BytesIO(json.dumps(body).encode())
        self.runtime.invoke_model.return_value = {"ResponseMetadata": {"RequestId": "titan-request"}, "body": self.stream}

    def test_real_adapter_arguments_and_closed_two_call_ledger(self):
        stored = self.invoke("store_source", self.document)
        self.embedding_response()
        embedded = self.invoke("embed", {"text": "합성 문서 본문입니다."})
        self.store.close(self.execution)
        self.assertEqual(self.s3.put_object.call_args.kwargs["Body"], self.document["content"].encode())
        self.assertEqual(self.s3.put_object.call_args.kwargs["Bucket"], "test-owned-bucket")
        args = self.runtime.invoke_model.call_args.kwargs
        self.assertEqual(args["modelId"], provider_module.MODEL)
        self.assertEqual(json.loads(args["body"]), {"inputText": "합성 문서 본문입니다.", "dimensions": 1024, "normalize": True})
        self.assertEqual(embedded["embedding_dimension"], 1024)
        self.assertEqual(embedded["embedding_norm"], 1)
        self.assertTrue(self.stream.closed)
        receipt = self.store.read(self.execution)
        self.assertTrue(receipt["closed"])
        self.assertEqual([row["response"] for row in receipt["calls"]], [stored, embedded])
        self.assertNotIn(self.document["content"], json.dumps(receipt, ensure_ascii=False))

    def test_wrong_key_stops_before_sdk_and_cannot_be_retried(self):
        with self.assertRaises(ledger_module.LedgerError):
            self.invoke("store_source", {**self.document, "key": "other/source.md"})
        self.s3.put_object.assert_not_called()
        with self.assertRaises(ledger_module.LedgerError):
            self.invoke("store_source", self.document)
        self.assertEqual(self.store.read(self.execution)["calls"][0]["state"], "error")

    def test_storage_timeout_does_not_claim_no_remote_effect(self):
        self.s3.put_object.side_effect = TimeoutError("private SDK message")
        with self.assertRaises(ledger_module.LedgerError) as caught:
            self.invoke("store_source", self.document)
        self.assertNotIn("private", str(caught.exception))
        self.store.close(self.execution)
        call = self.store.read(self.execution)["calls"][0]
        self.assertEqual(call["state"], "error")
        self.assertIsNone(call["provider_request_id"])
        self.runtime.invoke_model.assert_not_called()

    def test_embedding_failure_preserves_successful_storage(self):
        self.invoke("store_source", self.document)
        self.embedding_response(embedding=[0.0] * 1024)
        with self.assertRaises(ledger_module.LedgerError):
            self.invoke("embed", {"text": "합성 문서 본문입니다."})
        self.store.close(self.execution)
        self.assertEqual([row["state"] for row in self.store.read(self.execution)["calls"]], ["complete", "error"])
        self.s3.delete_object.assert_not_called()

    def test_source_requery_observes_mutation_instead_of_returning_old_digest(self):
        original = self.invoke("store_source", self.document)
        raw = b"changed content"
        stream = io.BytesIO(raw)
        self.s3.get_object.return_value = {"Body": stream, "ResponseMetadata": {"RequestId": "get-request"}}
        observed = self.provider.source_evidence(self.execution)
        self.assertNotEqual(original["source_digest"], observed["source_digest"])
        self.assertEqual(observed["source_bytes"], len(raw))
        self.assertTrue(stream.closed)

    def test_pending_reserved_before_sdk_side_effect(self):
        def put(**kwargs):
            self.assertEqual(self.store.read(self.execution)["calls"][0]["state"], "pending")
            with self.assertRaises(ledger_module.LedgerError):
                self.store.close(self.execution)
            return {"ResponseMetadata": {"RequestId": "s3-request"}}
        self.s3.put_object.side_effect = put
        self.invoke("store_source", self.document)

    def test_missing_provider_id_is_error_not_success(self):
        self.s3.put_object.return_value = {"ResponseMetadata": {}}
        with self.assertRaises(ledger_module.LedgerError):
            self.invoke("store_source", self.document)
        self.assertEqual(self.store.read(self.execution)["calls"][0]["state"], "error")

    def test_bad_embedding_types_are_rejected(self):
        for value in (True, float("nan"), float("inf"), "1"):
            execution = str(uuid4())
            token = self.store.register(self.suite, execution, "a" * 64, "b" * 64)["capability"]
            self.embedding_response(embedding=[value] + [0.0] * 1023)
            with self.assertRaises(ledger_module.LedgerError):
                self.provider.invoke(token, self.suite, execution, "embed", {"text": "test input"})
            self.assertTrue(self.stream.closed)

    def test_oversized_provider_response_is_closed_and_rejected(self):
        stream = io.BytesIO(b" " * 131073)
        self.runtime.invoke_model.return_value = {"body": stream, "ResponseMetadata": {"RequestId": "oversize"}}
        with self.assertRaises(ledger_module.LedgerError):
            self.invoke("embed", {"text": "test input"})
        self.assertTrue(stream.closed)
        self.assertEqual(self.store.read(self.execution)["calls"][0]["state"], "error")

    def test_absent_source_is_not_requeried_or_inferred(self):
        with self.assertRaises(ledger_module.LedgerError):
            self.provider.source_evidence(self.execution)
        self.s3.get_object.assert_not_called()

    def test_oversized_source_requery_does_not_return_partial_digest(self):
        self.invoke("store_source", self.document)
        stream = io.BytesIO(b"x" * 32769)
        self.s3.get_object.return_value = {"Body": stream, "ResponseMetadata": {"RequestId": "oversize"}}
        with self.assertRaises(ledger_module.LedgerError):
            self.provider.source_evidence(self.execution)
        self.assertTrue(stream.closed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
