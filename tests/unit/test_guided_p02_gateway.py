"""Configured Gateway contract provider and AWS client construction, no live AWS."""
import importlib.util
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway"
with patch.dict(sys.modules):
    for name in ("p02_ledger", "p02_provider", "p02_contract", "p02_api", "p02_resources", "p02_gateway"):
        spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
        value = importlib.util.module_from_spec(spec)
        sys.modules[name] = value
        spec.loader.exec_module(value)
    module = sys.modules["p02_gateway"]


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "gateway.sqlite3"
        self.state = {"status": "READY", "region": "us-east-1", "provider_mode": "contract",
                      "source_prefix": "h02/knowledge/", "source_bucket": "fixture-source"}
        self.control = {"Authorization": "Bearer control-fixture"}
        self.verifier = {"Authorization": "Bearer verifier-fixture"}
        self.suite, self.execution = str(uuid4()), str(uuid4())

    def client(self, mode="contract"):
        client = TestClient(module.configured_app(lambda: self.state, self.path,
                            provider_mode=mode, control_token="control-fixture", verifier_token="verifier-fixture", region="us-east-1"))
        self.addCleanup(client.close)
        return client

    def register(self, client):
        response = client.post("/executions", headers=self.control, json={"suite_id": self.suite,
                    "execution_id": self.execution, "source_digest": "a" * 64, "runner_digest": "b" * 64})
        self.assertEqual(response.status_code, 200)
        return {"Authorization": "Bearer " + response.json()["capability"]}

    def invoke(self, client, headers, operation, payload):
        return client.post("/invoke", headers=headers, json={"suite_id": self.suite, "execution_id": self.execution,
                            "operation": operation, "payload": payload})

    def test_contract_mode_persists_actual_source_and_marks_every_response(self):
        with patch.object(module.boto3, "client", side_effect=AssertionError("AWS must not be used")):
            client = self.client()
            headers = self.register(client)
            key = f"h02/knowledge/{self.execution}.md"
            stored = self.invoke(client, headers, "store_source", {"key": key, "content": "# 안내\n\n합성 본문입니다.\n"})
            embedded = self.invoke(client, headers, "embed", {"text": "합성 본문입니다."})
            self.assertEqual(stored.status_code, 200)
            self.assertEqual(embedded.status_code, 200)
            for result in (stored, embedded):
                self.assertEqual(result.json()["response"]["provider_mode"], "contract")
                self.assertTrue(result.json()["response"]["provider_request_id"].startswith("contract-"))
            self.assertAlmostEqual(embedded.json()["response"]["embedding_norm"], 1)
            self.assertEqual(client.post(f"/executions/{self.execution}/close", headers=self.control, json={}).status_code, 200)
            restarted = self.client()
            source = restarted.get(f"/executions/{self.execution}/source", headers=self.verifier)
            self.assertEqual(source.status_code, 200)
            self.assertEqual(source.json()["source_digest"], stored.json()["response"]["source_digest"])
            self.assertEqual(source.json()["provider_mode"], "contract")
            self.assertTrue(restarted.get(f"/executions/{self.execution}", headers=self.verifier).json()["closed"])

    def test_missing_resources_does_not_block_gateway_registration_or_make_aws_calls(self):
        self.state = None
        with patch.object(module.boto3, "client") as sdk:
            client = self.client()
            headers = self.register(client)
            self.assertEqual(self.invoke(client, headers, "embed", {"text": "test"}).status_code, 409)
            sdk.assert_not_called()

    def test_wrong_resource_mode_prefix_and_region_stop_before_client_creation(self):
        client = self.client()
        headers = self.register(client)
        for field, wrong in (("provider_mode", "aws"), ("source_prefix", "other/"), ("region", "eu-west-1")):
            with patch.dict(self.state, {field: wrong}), patch.object(module.boto3, "client") as sdk:
                self.assertEqual(self.invoke(client, headers, "embed", {"text": "test"}).status_code, 409)
                sdk.assert_not_called()

    def test_aws_clients_are_lazy_bounded_and_not_retried(self):
        self.state["provider_mode"] = "aws"
        s3 = Mock()
        s3.put_object.return_value = {"ResponseMetadata": {"RequestId": "sdk-double"}}
        with patch.object(module.boto3, "client", return_value=s3) as sdk:
            client = self.client("aws")
            headers = self.register(client)
            sdk.assert_not_called()
            response = self.invoke(client, headers, "store_source", {"key": f"h02/knowledge/{self.execution}.md", "content": "test source"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["response"]["provider_mode"], "aws")
            self.assertEqual([call.args[0] for call in sdk.call_args_list], ["s3", "bedrock-runtime"])
            for call in sdk.call_args_list:
                self.assertEqual(call.kwargs["region_name"], "us-east-1")
                config = call.kwargs["config"]
                self.assertEqual(config.retries["total_max_attempts"], 1)
                self.assertEqual((config.connect_timeout, config.read_timeout), (5, 20))


if __name__ == "__main__":
    unittest.main(verbosity=2)
