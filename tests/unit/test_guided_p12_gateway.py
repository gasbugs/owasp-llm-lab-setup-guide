"""Real P12 routes and durable grants with an explicit SDK double; no AWS."""
from pathlib import Path
import hashlib
import json
import os
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway"
sys.path.insert(0, str(ROOT))
from p12_capabilities import CapabilityStore, MODEL_ID
from p12_gateway import BedrockClient, create_app, configured_app, main_input_binding


class GatewayTests(unittest.TestCase):
    def test_real_adapter_does_not_require_a_client_context_manager(self):
        sdk = SimpleNamespace(converse=Mock(return_value={"fixture": True}), close=Mock())
        with patch("boto3.client", return_value=sdk) as factory:
            self.assertEqual(BedrockClient().converse(modelId=MODEL_ID), {"fixture": True})
        sdk.converse.assert_called_once_with(modelId=MODEL_ID)
        sdk.close.assert_called_once_with()
        config = factory.call_args.kwargs["config"]
        self.assertEqual(config.retries, {"total_max_attempts": 1})
        self.assertEqual(config.connect_timeout, 5)
        self.assertEqual(config.read_timeout, 55)

    def test_real_adapter_closes_client_after_provider_error(self):
        sdk = SimpleNamespace(converse=Mock(side_effect=RuntimeError("fixture")), close=Mock())
        with patch("boto3.client", return_value=sdk), self.assertRaises(RuntimeError):
            BedrockClient().converse(modelId=MODEL_ID)
        sdk.close.assert_called_once_with()

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = CapabilityStore(Path(self.temp.name) / "gateway.sqlite3")
        self.calls = []
        self.sdk = SimpleNamespace(converse=self.converse)
        self.client = TestClient(create_app(store=self.store, client=self.sdk,
                                           control_token="fixture-control", verifier_token="fixture-verifier"))
        self.suite, self.execution = str(uuid4()), str(uuid4())
        response = self.client.post("/v1/p12/suites", headers=self.headers("fixture-control"),
                                    json={"suite_id": self.suite, "execution_ids": [self.execution]})
        self.assertEqual(response.status_code, 200)
        self.grants = response.json()["grants"]

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return {"ResponseMetadata": {"RequestId": str(uuid4())}, "output": {"message": {
                "role": "assistant", "content": [{"text": "No"}]}}, "stopReason": "end_turn",
                "usage": {"inputTokens": 5, "outputTokens": 1, "totalTokens": 6}}

    def headers(self, token):
        return {"Authorization": "Bearer " + token}

    def invoke(self, grant=None, **updates):
        grant = grant or self.grants[0]
        body = {key: grant[key] for key in ("suite_id", "execution_id", "role", "model")}
        return self.client.post("/v1/p12/invoke", headers=self.headers(grant["capability"]),
                                json={**body, "prompt": "synthetic prompt", **updates})

    def test_roles_make_exactly_one_bound_sdk_call_each(self):
        for grant in self.grants:
            self.assertEqual(self.invoke(grant).status_code, 200)
            self.assertEqual(self.invoke(grant).status_code, 409)
        self.assertEqual(len(self.calls), 4)
        self.assertEqual([call["inferenceConfig"]["maxTokens"] for call in self.calls], [3, 3, 3, 128])
        self.assertTrue(all(call["modelId"] == MODEL_ID for call in self.calls))
        self.assertEqual(self.client.post(f"/v1/p12/suites/{self.suite}/close",
                         headers=self.headers("fixture-control"), json={}).status_code, 200)
        ledger = self.client.get(f"/v1/p12/suites/{self.suite}/ledger", headers=self.headers("fixture-verifier"))
        self.assertEqual(ledger.status_code, 200)
        self.assertTrue(all(row["state"] == "completed" for row in ledger.json()["grants"]))
        self.assertNotIn("synthetic prompt", ledger.text)

    def test_scope_and_caller_parameters_rejected_before_sdk(self):
        for updates in ({"role": "main"}, {"execution_id": str(uuid4())}, {"model": "another-model"}):
            self.assertEqual(self.invoke(**updates).status_code, 403)
        for updates in ({"max_tokens": 999}, {"temperature": 1}, {"task_completed": True}, {"prompt": " "}):
            response = self.invoke(**updates)
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.json(), {"detail": "invalid request fields"})
        self.assertFalse(self.calls)

    def test_control_and_verifier_are_not_invocation_capabilities(self):
        for token in ("fixture-control", "fixture-verifier"):
            grant = {**self.grants[0], "capability": token}
            self.assertEqual(self.invoke(grant).status_code, 401)
        self.assertEqual(self.client.get(f"/v1/p12/suites/{self.suite}/ledger",
                         headers=self.headers("fixture-control")).status_code, 401)
        self.assertEqual(self.client.post(f"/v1/p12/suites/{self.suite}/close",
                         headers=self.headers("fixture-verifier"), json={}).status_code, 401)
        self.assertFalse(self.calls)

    def test_sdk_failure_consumes_grant_and_hides_exception(self):
        def fail(**kwargs):
            self.calls.append(kwargs)
            raise RuntimeError("synthetic-private-value")
        self.sdk.converse = fail
        response = self.invoke()
        self.assertEqual(response.status_code, 502)
        self.assertNotIn("synthetic-private", response.text)
        self.assertEqual(self.invoke().status_code, 409)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(sum(row["state"] == "error" for row in self.store.ledger(self.suite)["grants"]), 1)

    def test_bad_provider_output_is_error_and_cannot_be_retried(self):
        def malformed(**kwargs):
            result = self.converse(**kwargs)
            result["output"]["message"]["content"] = [{"toolUse": {"name": "unexpected"}}]
            return result
        self.sdk.converse = malformed
        self.assertEqual(self.invoke().status_code, 502)
        self.assertEqual(self.invoke().status_code, 409)

    def test_invalid_classifier_remains_evidence_for_later_error_verdict(self):
        def malformed(**kwargs):
            result = self.converse(**kwargs)
            result["output"]["message"]["content"] = [{"text": "Yes\n"}]
            return result
        self.sdk.converse = malformed
        response = self.invoke()
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["evidence"]["classifier_schema_valid"])
        self.assertNotIn("security_verdict", response.json())

    def test_missing_or_non_aws_configuration_is_problem_local_503(self):
        for env in ({}, {"GUIDED_PROVIDER_MODE": "contract", "GUIDED_P12_GATEWAY_CONTROL_TOKEN": "control",
                         "GUIDED_P12_GATEWAY_VERIFIER_TOKEN": "verifier"}):
            with patch.dict(os.environ, env, clear=True):
                client = TestClient(configured_app())
            self.assertEqual(client.post("/invoke", json={}).status_code, 503)
        self.assertFalse(self.calls)

    def test_configured_subapp_starts_and_registers_without_aws_calls(self):
        env = {"GUIDED_PROVIDER_MODE": "aws", "GUIDED_P12_GATEWAY_CONTROL_TOKEN": "control",
               "GUIDED_P12_GATEWAY_VERIFIER_TOKEN": "verifier",
               "GUIDED_P12_GATEWAY_DATABASE": str(Path(self.temp.name) / "configured.sqlite3")}
        with patch.dict(os.environ, env, clear=True):
            client = TestClient(configured_app())
        response = client.post("/suites", headers=self.headers("control"),
                               json={"suite_id": str(uuid4()), "execution_ids": [str(uuid4())]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["grants"]), 4)

    def test_main_semantics_ignore_json_serialization_differences(self):
        values = {"question": "계정 복구 <EMAIL_ADDRESS>", "context": "지원 담당자에게 문의하세요."}
        prompts = [json.dumps(values, ensure_ascii=False), json.dumps(dict(reversed(list(values.items()))), indent=2),
                   json.dumps(values, separators=(",", ":"))]
        bindings = [main_input_binding(prompt) for prompt in prompts]
        self.assertEqual(len({b["prompt_digest"] for b in bindings}), 3)
        for key in values:
            self.assertEqual({b[key + "_digest"] for b in bindings}, {hashlib.sha256(values[key].encode()).hexdigest()})
        self.assertTrue(all(b["schema_valid"] for b in bindings))

    def test_actual_sdk_prompt_is_bound_without_recording_raw_fields(self):
        grant = next(g for g in self.grants if g["role"] == "main")
        prompt = json.dumps({"context": "private-context-fixture", "question": "private-question-fixture"}, indent=2)
        response = self.invoke(grant, prompt=prompt)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.calls[0]["messages"][0]["content"][0]["text"], prompt)
        self.assertEqual(response.json()["evidence"]["main_input"], main_input_binding(prompt))
        row = next(g for g in self.store.ledger(self.suite)["grants"] if g["role"] == "main")
        self.assertEqual(row["evidence"]["main_input"], response.json()["evidence"]["main_input"])
        self.assertNotIn("private-context-fixture", json.dumps(row))
        self.assertNotIn("private-question-fixture", json.dumps(row))

    def test_ambiguous_or_invalid_main_input_is_not_valid_evidence(self):
        for prompt in ('plain prompt', '[]', '{"question":"x","context":"y","extra":1}',
                       '{"question":"x","question":"z","context":"y"}', '{"question":true,"context":"y"}',
                       '{"question":" ","context":"y"}', '{"question":"x","context":""}'):
            with self.subTest(prompt=prompt):
                binding = main_input_binding(prompt)
                self.assertIs(binding["schema_valid"], False)
                self.assertEqual(set(binding), {"schema_valid", "prompt_digest"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
