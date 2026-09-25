"""P01 learner execution tests with deterministic SDK responses; no AWS calls."""

from contextlib import contextmanager
from datetime import datetime, timezone
import importlib.util
import os
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid
from concurrent.futures import ThreadPoolExecutor
import threading

from fastapi.testclient import TestClient
from botocore.stub import Stubber


LAB = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs/h01-bedrock-gateway"


def valid(body, client):
    if set(body) != {"message", "max_output_tokens"}:
        raise ValueError("fields")
    message, tokens = body["message"], body["max_output_tokens"]
    if not isinstance(message, str) or not message.strip() or not 1 <= len(message) <= 4000:
        raise ValueError("message")
    if type(tokens) is not int or not 1 <= tokens <= 512:
        raise ValueError("tokens")
    return client.converse(
        modelId="us.amazon.nova-lite-v1:0",
        messages=[{"role": "user", "content": [{"text": message}]}],
        inferenceConfig={"maxTokens": min(tokens, 128), "temperature": 0.0},
    )


def alternate(body, client):
    if sorted(body) != ["max_output_tokens", "message"]:
        raise ValueError("fields")
    text = body.get("message")
    count = body.get("max_output_tokens")
    if type(text) is not str or len(text) > 4000 or text.strip() == "":
        raise ValueError("text")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1 or count > 512:
        raise ValueError("count")
    if count > 128:
        count = 128
    parameters = dict(maxTokens=count, temperature=0.0)
    return client.converse(modelId="us.amazon.nova-lite-v1:0", inferenceConfig=parameters,
                           messages=[dict(role="user", content=[dict(text=text)])])


class P01GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="p01-gateway-test-")
        with patch.dict(os.environ, {
            "GUIDED_CONTROL_LAB01_TOKEN": "unit-control",
            "GUIDED_VERIFIER_LAB01_TOKEN": "unit-verifier",
            "GUIDED_PROVIDER_MODE": "contract",
            "GUIDED_LAB01_DATABASE": str(Path(cls.temp.name) / "receipts.sqlite3"),
        }), patch.dict(sys.modules):
            for name in ("learner", "provider", "p01_gateway_test"):
                filename = "server.py" if name == "p01_gateway_test" else f"{name}.py"
                spec = importlib.util.spec_from_file_location(name, LAB / filename)
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                spec.loader.exec_module(module)
            cls.server = module

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextmanager
    def implementation(self, function):
        with patch.object(self.server.learner, "handle_request", function), TestClient(self.server.app) as client:
            yield client

    def request(self, client, body, token="unit-control"):
        metadata = dict(execution_id=str(uuid.uuid4()), started_at=datetime.now(timezone.utc).isoformat(), scenario="normal")
        return client.post("/v1/chat", json={**metadata, **body}, headers={"Authorization": f"Bearer {token}"})

    def test_starter_is_incomplete_without_model_call(self):
        with TestClient(self.server.app) as client, patch.object(self.server.RecordingClient, "converse") as call:
            self.assertEqual(self.request(client, {"message": "hello", "max_output_tokens": 64}).status_code, 501)
            call.assert_not_called()

    def test_learner_edit_changes_identity_but_not_provided_runner(self):
        with tempfile.TemporaryDirectory(prefix="p01-identity-") as temporary:
            root = Path(temporary)
            for name in ("server.py", "provider.py", "learner.py"):
                (root / name).write_bytes((LAB / name).read_bytes())
            with patch.object(self.server, "SOURCE_PATH", root / "server.py"):
                original_source = self.server.source_digest()
                original_runner = self.server.runner_digests()
                self.assertEqual(set(original_runner), {"server.py", "provider.py"})
                with (root / "learner.py").open("a") as output:
                    output.write("\n# Harmless learner comment\n")
                self.assertNotEqual(self.server.source_digest(), original_source)
                self.assertEqual(self.server.runner_digests(), original_runner)
                with (root / "provider.py").open("a") as output:
                    output.write("\n# Modified provided runner\n")
                self.assertNotEqual(self.server.runner_digests(), original_runner)

    def test_two_equivalent_implementations_execute_actual_parameters(self):
        for implementation in (valid, alternate):
            with self.subTest(implementation=implementation.__name__), self.implementation(implementation) as client:
                for tokens in (1, 37, 64, 127, 128, 129, 301, 512):
                    response = self.request(client, {"message": f"문장 {tokens}", "max_output_tokens": tokens})
                    self.assertEqual(response.status_code, 200, response.text)
                    receipt = response.json()
                    self.assertEqual(receipt["forwarded_parameters"], {"maxTokens": min(tokens, 128), "temperature": 0.0})
                    self.assertEqual(receipt["forwarded_messages"][0]["content"][0]["text"], f"문장 {tokens}")
                    self.assertEqual((receipt["activity_id"], receipt["internal_activity_id"], receipt["contract_version"]), ("P01", "H01", 2))
                    self.assertEqual(receipt["provider_mode"], "contract")
                    saved = client.get(f'/v1/receipts/{receipt["execution_id"]}', headers={"Authorization": "Bearer unit-verifier"})
                    self.assertEqual(saved.json(), receipt)

    def test_invalid_inputs_stop_before_provider(self):
        bodies = [{}, {"message": "hello"}, {"message": "hello", "max_output_tokens": 64, "model": "other"}]
        bodies += [{"message": value, "max_output_tokens": 64} for value in (None, 12, "", "  ", "x" * 4001)]
        bodies += [{"message": "hello", "max_output_tokens": value} for value in (None, True, False, 1.0, "64", 0, -1, 513)]
        for implementation in (valid, alternate):
            with self.implementation(implementation) as client, patch.object(self.server.RecordingClient, "converse") as call:
                for body in bodies:
                    self.assertEqual(self.request(client, body).status_code, 422, body)
                call.assert_not_called()

    def test_shared_published_contract_against_both_real_implementations(self):
        contract = json.loads((LAB.parents[1] / "guided-contracts/p01.json").read_text())
        self.assertEqual(len(contract["cases"]), 21)
        for implementation in (valid, alternate):
            with self.implementation(implementation) as client:
                for case in contract["cases"]:
                    with self.subTest(implementation=implementation.__name__, case=case["case_id"]):
                        response = self.request(client, case["body"])
                        self.assertEqual(response.status_code, case["expected_status"])
                        if case["expected_status"] == 200:
                            self.assertEqual(response.json()["effective_max_output_tokens"], case["effective_max_tokens"])

    def test_missing_auth_does_not_run_learner(self):
        with self.implementation(valid) as client, patch.object(self.server.learner, "handle_request") as handler:
            self.assertEqual(self.request(client, {}, token="wrong").status_code, 401)
            handler.assert_not_called()

    def test_aws_credentials_are_not_loaded_for_invalid_or_incomplete_requests(self):
        with patch.object(self.server, "PROVIDER_MODE", "aws"), patch.object(self.server.boto3, "client") as sdk:
            with TestClient(self.server.app) as client:
                self.assertEqual(self.request(client, {"message": "hello", "max_output_tokens": 64}).status_code, 501)
            with self.implementation(valid) as client:
                self.assertEqual(self.request(client, {"message": "", "max_output_tokens": 64}).status_code, 422)
            sdk.assert_not_called()

    def test_fabricated_response_without_call_is_not_evidence(self):
        with self.implementation(lambda body, client: {"usage": {"outputTokens": 10}}) as client:
            self.assertEqual(self.request(client, {"message": "hello", "max_output_tokens": 64}).status_code, 502)

    def test_real_boto3_interface_with_stubbed_transport(self):
        sdk = self.server.boto3.client("bedrock-runtime", region_name="us-east-1",
                                      aws_access_key_id="unit-only", aws_secret_access_key="unit-only")
        result = {
            "ResponseMetadata": {"RequestId": "stubbed-sdk-request"},
            "output": {"message": {"role": "assistant", "content": [{"text": "hello"}]}},
            "stopReason": "end_turn",
            "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
            "metrics": {"latencyMs": 1},
        }
        with Stubber(sdk) as stub:
            stub.add_response("converse", result, {
                "modelId": "us.amazon.nova-lite-v1:0",
                "messages": [{"role": "user", "content": [{"text": "hello"}]}],
                "inferenceConfig": {"maxTokens": 128, "temperature": 0.0},
            })
            with patch.object(self.server, "PROVIDER_MODE", "aws"), patch.object(self.server.boto3, "client", return_value=sdk), self.implementation(valid) as client:
                response = self.request(client, {"message": "hello", "max_output_tokens": 301})
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json()["provider_request_id"], "stubbed-sdk-request")
            stub.assert_no_pending_responses()
        sdk.close()

    def test_second_call_cannot_be_hidden_by_catching_error(self):
        def twice(body, client):
            result = valid(body, client)
            try:
                valid(body, client)
            except RuntimeError:
                pass
            return result
        with self.implementation(twice) as client:
            self.assertEqual(self.request(client, {"message": "hello", "max_output_tokens": 64}).status_code, 502)

    def test_unlimited_policy_remains_observable_not_silently_fixed(self):
        def missing_limit(body, client):
            return client.converse(modelId="us.amazon.nova-lite-v1:0", messages=[{"role": "user", "content": [{"text": body["message"]}]}],
                                   inferenceConfig={"maxTokens": body["max_output_tokens"], "temperature": 0.0})
        with self.implementation(missing_limit) as client:
            receipt = self.request(client, {"message": "hello", "max_output_tokens": 512}).json()
            self.assertEqual(receipt["effective_max_output_tokens"], 512)
            self.assertNotIn("task_completed", receipt)
            self.assertNotIn("course_verdict", receipt)

    def test_modified_provider_response_is_rejected(self):
        def modified(body, client):
            result = valid(body, client)
            result["usage"]["outputTokens"] = 0
            return result
        with self.implementation(modified) as client:
            self.assertEqual(self.request(client, {"message": "hello", "max_output_tokens": 64}).status_code, 502)

    def test_rejected_request_has_closed_zero_call_record(self):
        execution_id = str(uuid.uuid4())
        body = dict(execution_id=execution_id, started_at=datetime.now(timezone.utc).isoformat(), scenario="normal", message="", max_output_tokens=64)
        with self.implementation(valid) as client:
            response = client.post("/v1/chat", json=body, headers={"Authorization": "Bearer unit-control"})
            self.assertEqual(response.status_code, 422)
            record = client.get(f"/v1/executions/{execution_id}", headers={"Authorization": "Bearer unit-verifier"}).json()
            self.assertTrue(record["closed"])
            self.assertEqual((record["http_status"], record["invocation_attempts"], record["provider_attempts"], record["provider_results"]), (422, 0, 0, 0))
            self.assertEqual(record["provider_request_ids"], [])
            self.assertEqual(client.get(f"/v1/executions/{execution_id}").status_code, 401)

    def test_provider_error_is_recorded_not_treated_as_no_call(self):
        from botocore.exceptions import BotoCoreError
        execution_id = str(uuid.uuid4())
        body = dict(execution_id=execution_id, started_at=datetime.now(timezone.utc).isoformat(), scenario="normal", message="hello", max_output_tokens=64)
        with self.implementation(valid) as client, patch.object(self.server, "PROVIDER_MODE", "aws"), patch.object(self.server.boto3, "client") as sdk:
            sdk.return_value.converse.side_effect = BotoCoreError()
            response = client.post("/v1/chat", json=body, headers={"Authorization": "Bearer unit-control"})
            self.assertEqual(response.status_code, 502)
            record = client.get(f"/v1/executions/{execution_id}", headers={"Authorization": "Bearer unit-verifier"}).json()
            self.assertTrue(record["closed"])
            self.assertEqual((record["http_status"], record["provider_attempts"], record["provider_results"]), (502, 1, 0))

    def test_simultaneous_duplicate_execution_is_reserved_before_invocation(self):
        entered, release = threading.Event(), threading.Event()
        request = self.server.ChatRequest(execution_id=str(uuid.uuid4()), started_at=datetime.now(timezone.utc).isoformat(), scenario="normal", message="hello", max_output_tokens=64)
        def slow(body, client):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test synchronization timeout")
            return valid(body, client)
        with patch.object(self.server.learner, "handle_request", slow), ThreadPoolExecutor(max_workers=2) as pool:
            future = pool.submit(self.server.chat, request, None)
            try:
                self.assertTrue(entered.wait(3))
                with self.assertRaises(self.server.HTTPException) as error:
                    self.server.chat(request, None)
                self.assertEqual(error.exception.status_code, 409)
                record = self.server.execution(request.execution_id, None)
                self.assertFalse(record["closed"])
            finally:
                release.set()
            self.assertEqual(future.result(timeout=5)["effective_max_output_tokens"], 64)


if __name__ == "__main__":
    unittest.main()
