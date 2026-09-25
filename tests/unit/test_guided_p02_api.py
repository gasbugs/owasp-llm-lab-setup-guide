"""Real API, SQLite ledger and SDK adapter using local SDK doubles."""
import importlib.util
import io
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock
from uuid import uuid4

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway"


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


ledger_module = load("p02_ledger")
previous = sys.modules.get("p02_ledger")
sys.modules["p02_ledger"] = ledger_module
try:
    api, provider_module = load("p02_api"), load("p02_provider")
finally:
    if previous is None:
        del sys.modules["p02_ledger"]
    else:
        sys.modules["p02_ledger"] = previous


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ledger = ledger_module.DocumentLedger(Path(self.temp.name) / "state.sqlite3")
        self.s3, self.runtime = Mock(), Mock()
        self.provider = provider_module.DocumentProvider(self.ledger, self.s3, self.runtime, "fixture-bucket")
        self.factory = Mock(return_value=self.provider)
        self.client = TestClient(api.create_app(self.ledger, self.factory, control_token="control-fixture", verifier_token="verifier-fixture"))
        self.addCleanup(self.client.close)
        self.control = {"Authorization": "Bearer control-fixture"}
        self.verifier = {"Authorization": "Bearer verifier-fixture"}
        self.registration = {"suite_id": str(uuid4()), "execution_id": str(uuid4()),
                             "source_digest": "a" * 64, "runner_digest": "b" * 64}
        result = self.client.post("/executions", headers=self.control, json=self.registration)
        self.assertEqual(result.status_code, 200)
        self.grant = {"Authorization": "Bearer " + result.json()["capability"]}
        self.path = "/executions/" + self.registration["execution_id"]

    def invoke(self, operation, payload, headers=None):
        return self.client.post("/invoke", headers=self.grant if headers is None else headers,
                                json={"suite_id": self.registration["suite_id"],
                                      "execution_id": self.registration["execution_id"],
                                      "operation": operation, "payload": payload})

    def test_valid_invocation_closed_ledger_and_readonly_source_requery(self):
        raw = "# 안내\n\n합성 테스트입니다.\n".encode()
        self.s3.put_object.return_value = {"ResponseMetadata": {"RequestId": "put"}}
        stored = self.invoke("store_source", {"key": f"h02/knowledge/{self.registration['execution_id']}.md", "content": raw.decode()})
        self.assertEqual(stored.status_code, 200)
        self.runtime.invoke_model.return_value = {"ResponseMetadata": {"RequestId": "embed"},
            "body": io.BytesIO(json.dumps({"embedding": [1.0] + [0.0] * 1023, "inputTextTokenCount": 5}).encode())}
        self.assertEqual(self.invoke("embed", {"text": "합성 테스트입니다."}).status_code, 200)
        self.assertEqual(self.client.post(self.path + "/close", headers=self.control, json={}).status_code, 200)
        receipt = self.client.get(self.path, headers=self.verifier).json()
        self.assertTrue(receipt["closed"])
        self.assertEqual(len(receipt["calls"]), 2)
        self.s3.get_object.return_value = {"ResponseMetadata": {"RequestId": "get"}, "Body": io.BytesIO(raw)}
        source = self.client.get(self.path + "/source", headers=self.verifier).json()
        self.assertEqual(source["source_digest"], stored.json()["response"]["source_digest"])

    def test_capability_cannot_register_close_or_read(self):
        self.assertEqual(self.client.post("/executions", headers=self.grant, json=self.registration).status_code, 401)
        self.assertEqual(self.client.post(self.path + "/close", headers=self.grant, json={}).status_code, 401)
        self.assertEqual(self.client.get(self.path, headers=self.grant).status_code, 401)
        self.assertEqual(self.client.get(self.path + "/source", headers=self.grant).status_code, 401)
        self.factory.assert_not_called()

    def test_verifier_cannot_write_and_control_cannot_read(self):
        self.assertEqual(self.client.post(self.path + "/close", headers=self.verifier, json={}).status_code, 401)
        self.assertEqual(self.client.get(self.path, headers=self.control).status_code, 401)
        self.assertEqual(self.invoke("embed", {"text": "test"}, self.verifier).status_code, 401)
        self.runtime.invoke_model.assert_not_called()

    def test_unknown_evidence_is_404_not_zero_calls(self):
        result = self.client.get("/executions/" + str(uuid4()), headers=self.verifier)
        self.assertEqual(result.status_code, 404)
        self.assertNotIn("calls", result.json())

    def test_pending_closure_is_conflict(self):
        capability = self.grant["Authorization"].split()[1]
        self.ledger.reserve(capability, self.registration["suite_id"], self.registration["execution_id"], "embed", "c" * 64)
        self.assertEqual(self.client.post(self.path + "/close", headers=self.control, json={}).status_code, 409)

    def test_verdict_fields_and_invented_operations_are_rejected(self):
        self.assertEqual(self.client.post(self.path + "/close", headers=self.control, json={"task_completed": True}).status_code, 422)
        self.assertEqual(self.client.post("/executions", headers=self.control,
                                         json={**self.registration, "course_verdict": "PASS"}).status_code, 422)
        self.assertEqual(self.invoke("delete_source", {}).status_code, 422)
        self.factory.assert_not_called()

    def test_sdk_error_is_redacted_and_ledger_retains_attempt(self):
        self.runtime.invoke_model.side_effect = RuntimeError("private error text")
        result = self.invoke("embed", {"text": "test"})
        self.assertEqual(result.status_code, 502)
        self.assertNotIn("private", result.text)
        receipt = self.client.get(self.path, headers=self.verifier).json()
        self.assertEqual(receipt["calls"][0]["state"], "error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
