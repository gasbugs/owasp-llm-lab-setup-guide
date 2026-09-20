"""HTTP boundary checks with an explicitly mocked Bedrock transport."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "llm-security-control-plane"
sys.path.insert(0, str(CONTROL / "bedrock-gateway"))
sys.path.insert(0, str(CONTROL / "shared"))
with patch.dict(os.environ, {"BEDROCK_GATEWAY_TOKEN": "unit-only", "AWS_EC2_METADATA_DISABLED": "true"}), patch("boto3.client"):
    spec = importlib.util.spec_from_file_location("runtime_gateway_http", CONTROL / "bedrock-gateway/server.py")
    server = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = server
    spec.loader.exec_module(server)


class GatewayHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        folder = Path(self.tmp.name)
        policy = {"window_seconds": 3600, "clients": {
            "team-a": {"credential_sha256": hashlib.sha256(b"unit-a").hexdigest(),
                       "models": [server.MODEL_ID], "requests": 1, "output_tokens": 10,
                       "max_output_tokens": 10, "max_input_bytes": 100}}}
        (folder / "policy.json").write_text(json.dumps(policy))
        server.OPERATIONS = server.GatewayOperations(str(folder / "policy.json"), str(folder / "usage.db"))
        server.RUNTIME["ready"] = True
        self.bedrock = Mock()
        self.bedrock.converse.return_value = {
            "output": {"message": {"content": [{"text": "unit response"}]}},
            "usage": {"inputTokens": 3, "outputTokens": 2, "totalTokens": 5}, "stopReason": "end_turn"}
        server.BEDROCK = self.bedrock
        self.client = TestClient(server.app, raise_server_exceptions=False)
        self.headers = {"Authorization": "Bearer unit-a"}
        self.body = {"model": server.MODEL_ID, "messages": [{"role": "user", "content": "hello"}], "max_tokens": 10}

    def test_authentication_denies_before_provider(self):
        response = self.client.post("/v1/chat/completions", json=self.body)
        self.assertEqual(response.status_code, 401)
        self.bedrock.converse.assert_not_called()

    def test_model_denies_before_provider(self):
        response = self.client.post("/v1/chat/completions", headers=self.headers, json={**self.body, "model": "other"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(response.json()["detail"]["upstream_called"])
        self.bedrock.converse.assert_not_called()

    def test_body_cannot_declare_identity(self):
        response = self.client.post("/v1/chat/completions", headers=self.headers, json={**self.body, "principal": "team-b"})
        self.assertEqual(response.status_code, 422)
        self.bedrock.converse.assert_not_called()

    def test_normal_then_quota_and_private_usage(self):
        first = self.client.post("/v1/chat/completions", headers=self.headers, json=self.body)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["gateway_policy"]["principal"], "team-a")
        second = self.client.post("/v1/chat/completions", headers=self.headers, json=self.body)
        self.assertEqual(second.status_code, 429)
        self.assertEqual(self.bedrock.converse.call_count, 1)
        usage = self.client.get("/v1/usage", headers=self.headers).json()
        self.assertEqual((usage["input_tokens"], usage["output_tokens"], usage["output_reserved"]), (3, 2, 0))
        self.assertNotIn("credential", json.dumps(usage))
        self.assertEqual(self.client.get("/v1/usage").status_code, 401)

    def test_provider_error_keeps_reservation(self):
        from botocore.exceptions import ReadTimeoutError
        self.bedrock.converse.side_effect = ReadTimeoutError(endpoint_url="unit-transport")
        response = self.client.post("/v1/chat/completions", headers=self.headers, json=self.body)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(server.OPERATIONS.usage("team-a")["output_reserved"], 10)

    def test_retrieval_does_not_bypass_operational_scope(self):
        response = self.client.post("/v1/retrieve", headers=self.headers, json={"query": "hello"})
        self.assertEqual(response.status_code, 403)

    def test_missing_provider_usage_is_not_a_zero_cost_success(self):
        self.bedrock.converse.return_value.pop("usage")
        response = self.client.post("/v1/chat/completions", headers=self.headers, json=self.body)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(server.OPERATIONS.usage("team-a")["output_reserved"], 10)

    def test_invalid_transport_has_no_reservation_or_provider_call(self):
        for patch_body in ({"stream": True}, {"response_format": {"type": "unsupported"}},
                           {"messages": [{"role": "system", "content": "hello"}]}):
            response = self.client.post("/v1/chat/completions", headers=self.headers,
                                        json={**self.body, **patch_body})
            self.assertEqual(response.status_code, 422)
        self.assertEqual(server.OPERATIONS.usage("team-a")["requests"], 0)
        self.bedrock.converse.assert_not_called()

    def test_excess_provider_usage_retains_reservation(self):
        self.bedrock.converse.return_value["usage"]["outputTokens"] = 11
        response = self.client.post("/v1/chat/completions", headers=self.headers, json=self.body)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(server.OPERATIONS.usage("team-a")["output_reserved"], 10)

    def test_legacy_configuration_remains_usable(self):
        server.OPERATIONS = None
        response = self.client.post("/v1/chat/completions", headers={"Authorization": "Bearer unit-only"}, json=self.body)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("gateway_policy", response.json())
        self.assertEqual(self.client.get("/v1/usage", headers={"Authorization": "Bearer unit-only"}).status_code, 404)


if __name__ == "__main__":
    unittest.main()
