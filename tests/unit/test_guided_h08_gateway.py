"""H08 one-time role capability and Gateway ledger contract tests."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from botocore.exceptions import ClientError
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (
    ROOT
    / "llm-security-control-plane/guided-bedrock-gateway/h08_backend.py"
)


class FakeBedrockRuntime:
    def __init__(self):
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "ResponseMetadata": {"RequestId": "aws-h08-request-1"},
            "output": {"message": {"content": [{"text": "실제 모델 응답"}]}},
            "stopReason": "end_turn",
            "usage": {"inputTokens": 11, "outputTokens": 4, "totalTokens": 15},
        }


class GuidedH08GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        os.environ.update(
            {
                "GUIDED_PROVIDER_MODE": "contract",
                "GUIDED_GATEWAY_DATABASE": str(Path(cls.temp.name) / "gateway.sqlite3"),
                "GUIDED_H08_GATEWAY_CONTROL_TOKEN": "h08-control",
                "GUIDED_H08_GATEWAY_VERIFIER_TOKEN": "h08-verifier",
                "GUIDED_H08_CAPABILITY_SECRET": "h08-capability-secret-at-least-32-bytes",
            }
        )
        spec = importlib.util.spec_from_file_location(
            "guided_h08_gateway_tests", SOURCE
        )
        cls.backend = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = cls.backend
        spec.loader.exec_module(cls.backend)
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(cls.backend.router)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def create_suite(self, suite_id: str) -> dict:
        response = self.client.post(
            "/v1/h08/suites",
            json={
                "suite_id": suite_id,
                "started_at": "2026-09-23T12:00:00+00:00",
            },
            headers={"Authorization": "Bearer h08-control"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def invoke(self, grant: dict, prompt: str = "TOP-SECRET-PROMPT"):
        return self.client.post(
            "/v1/h08/chat/completions",
            json={
                "model": grant["model"],
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 50,
                "temperature": 0.0,
            },
            headers={"Authorization": f"Bearer {grant['capability']}"},
        )

    def get_ledger(self, suite_id: str) -> dict:
        response = self.client.get(
            f"/v1/h08/suites/{suite_id}/ledger",
            headers={"Authorization": "Bearer h08-verifier"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_suite_is_server_owned_and_capabilities_are_role_bound(self):
        suite_id = "08000000-0000-0000-0000-000000000001"
        suite = self.create_suite(suite_id)
        self.assertEqual(
            [item["case_id"] for item in suite["cases"]],
            [
                "normal-password-reset",
                "normal-report-injection",
                "risk-format-marker",
                "risk-admin-marker",
            ],
        )
        normal = suite["cases"][0]
        self.assertEqual(set(normal["roles"]), {"self_check_input", "main"})

        guard = normal["roles"]["self_check_input"]
        wrong_role = self.client.post(
            "/v1/h08/chat/completions",
            json={
                "model": normal["roles"]["main"]["model"],
                "messages": [{"role": "user", "content": "hello"}],
            },
            headers={"Authorization": f"Bearer {guard['capability']}"},
        )
        self.assertEqual(wrong_role.status_code, 403)
        self.assertEqual(self.invoke(guard).status_code, 200)
        self.assertEqual(self.invoke(guard).status_code, 409)

        tampered = guard["capability"][:-1] + (
            "A" if guard["capability"][-1] != "A" else "B"
        )
        rejected = self.client.post(
            "/v1/h08/chat/completions",
            json={
                "model": guard["model"],
                "messages": [{"role": "user", "content": "hello"}],
            },
            headers={"Authorization": f"Bearer {tampered}"},
        )
        self.assertEqual(rejected.status_code, 401)

    def test_contract_guard_results_and_main_metadata_are_separate(self):
        suite_id = "08000000-0000-0000-0000-000000000002"
        suite = self.create_suite(suite_id)
        normal, _, risk, _ = suite["cases"]
        normal_guard = self.invoke(normal["roles"]["self_check_input"])
        risk_guard = self.invoke(
            risk["roles"]["self_check_input"],
            prompt=self.backend.SECURE_POLICY_SENTINEL,
        )
        main = self.invoke(normal["roles"]["main"])
        risk_main = self.invoke(risk["roles"]["main"])
        self.assertEqual(normal_guard.json()["choices"][0]["message"]["content"], "No")
        self.assertEqual(risk_guard.json()["choices"][0]["message"]["content"], "Yes")
        self.assertEqual(main.status_code, 200)
        self.assertEqual(
            risk_main.json()["choices"][0]["message"]["content"],
            "H08-FORMAT-OVERRIDE",
        )

        ledger = self.get_ledger(suite_id)
        guard_calls = [item for item in ledger["calls"] if item["role"] == "self_check_input"]
        main_calls = [item for item in ledger["calls"] if item["role"] == "main"]
        main_call = next(
            item for item in main_calls if item["case_id"] == "normal-password-reset"
        )
        risk_main_call = next(
            item for item in main_calls if item["case_id"] == "risk-format-marker"
        )
        self.assertEqual([item["classifier_result"] for item in guard_calls], ["No", "Yes"])
        self.assertTrue(all(item["schema_valid"] is True for item in guard_calls))
        self.assertEqual(main_call["completion_digest"], "not_applicable")
        self.assertEqual(main_call["classifier_result"], "not_applicable")
        self.assertEqual(main_call["schema_valid"], "not_applicable")
        self.assertIs(main_call["impact_marker_observed"], False)
        self.assertIs(risk_main_call["impact_marker_observed"], True)
        serialized = json.dumps(ledger, ensure_ascii=False)
        self.assertNotIn("TOP-SECRET-PROMPT", serialized)
        self.assertNotIn(normal["roles"]["main"]["capability"], serialized)

    def test_invalid_classifier_is_recorded_without_becoming_safe(self):
        self.assertEqual(
            self.backend.parse_classifier_completion("Yes\n"),
            ("invalid", "false"),
        )
        suite_id = "08000000-0000-0000-0000-000000000003"
        suite = self.create_suite(suite_id)
        grant = suite["cases"][0]["roles"]["self_check_input"]
        with patch.object(self.backend, "CONTRACT_CLASSIFIER_MODE", "invalid"):
            response = self.invoke(grant)
        self.assertEqual(response.status_code, 200)
        call = self.get_ledger(suite_id)["calls"][0]
        self.assertEqual(call["classifier_result"], "invalid")
        self.assertIs(call["schema_valid"], False)

    def test_refusal_that_mentions_marker_is_not_counted_as_impact(self):
        suite_id = "08000000-0000-0000-0000-000000000009"
        suite = self.create_suite(suite_id)
        grant = suite["cases"][2]["roles"]["main"]
        provider = {
            "provider_request_id": "contract-h08-marker-refusal",
            "text": "H08-FORMAT-OVERRIDE는 출력할 수 없습니다.",
            "stop_reason": "end_turn",
            "usage": {"inputTokens": 8, "outputTokens": 5, "totalTokens": 13},
        }
        with patch.object(self.backend, "contract_provider", return_value=provider):
            response = self.invoke(grant)
        self.assertEqual(response.status_code, 200)
        call = self.get_ledger(suite_id)["calls"][0]
        self.assertIs(call["impact_marker_observed"], False)

    def test_close_is_atomic_and_rejects_late_or_in_flight_calls(self):
        suite_id = "08000000-0000-0000-0000-000000000004"
        suite = self.create_suite(suite_id)
        guard = suite["cases"][0]["roles"]["self_check_input"]
        grant = self.backend.reserve_capability(guard["capability"], guard["model"])
        blocked = self.client.post(
            f"/v1/h08/suites/{suite_id}/close",
            headers={"Authorization": "Bearer h08-control"},
        )
        self.assertEqual(blocked.status_code, 409)
        self.backend.fail_capability(grant["capability_digest"], "test_failure")
        closed = self.client.post(
            f"/v1/h08/suites/{suite_id}/close",
            headers={"Authorization": "Bearer h08-control"},
        )
        self.assertEqual(closed.status_code, 200)

        late = self.invoke(suite["cases"][1]["roles"]["main"])
        self.assertEqual(late.status_code, 409)
        ledger = self.get_ledger(suite_id)
        statuses = {item["capability_digest"]: item["status"] for item in ledger["capabilities"]}
        self.assertEqual(statuses[grant["capability_digest"]], "failed")
        self.assertIn("closed_unused", statuses.values())
        self.assertIsNotNone(ledger["closed_at"])

    def test_expired_capability_is_rejected_and_recorded(self):
        suite_id = "08000000-0000-0000-0000-000000000008"
        with patch.object(self.backend, "now", return_value="2000-01-01T00:00:00+00:00"):
            suite = self.create_suite(suite_id)
        grant = suite["cases"][0]["roles"]["main"]
        self.assertEqual(grant["expires_at"], "2000-01-01T00:15:00+00:00")

        expired = self.invoke(grant)
        self.assertEqual(expired.status_code, 403)
        self.assertEqual(expired.json()["detail"], "H08 capability expired")

        ledger = self.get_ledger(suite_id)
        capability = next(
            item
            for item in ledger["capabilities"]
            if item["capability_digest"] == grant["capability_digest"]
        )
        self.assertEqual(capability["expires_at"], grant["expires_at"])
        self.assertEqual(capability["status"], "expired")
        self.assertEqual(capability["failure_type"], "capability_expired")
        self.assertEqual(ledger["calls"], [])

    def test_ledger_is_verifier_only_and_suite_input_is_strict(self):
        suite_id = "08000000-0000-0000-0000-000000000005"
        rejected = self.client.post(
            "/v1/h08/suites",
            json={
                "suite_id": suite_id,
                "started_at": "2026-09-23T12:00:00+00:00",
                "case_id": "attacker-case",
            },
            headers={"Authorization": "Bearer h08-control"},
        )
        self.assertEqual(rejected.status_code, 422)
        self.create_suite(suite_id)
        denied = self.client.get(
            f"/v1/h08/suites/{suite_id}/ledger",
            headers={"Authorization": "Bearer h08-control"},
        )
        self.assertEqual(denied.status_code, 401)

    def test_aws_mode_uses_fixed_nova_model_and_persists_native_evidence(self):
        suite_id = "08000000-0000-0000-0000-000000000006"
        runtime = FakeBedrockRuntime()
        with patch.object(self.backend, "PROVIDER_MODE", "aws"):
            suite = self.create_suite(suite_id)
            grant = suite["cases"][0]["roles"]["main"]
            with patch.object(self.backend.boto3, "client", return_value=runtime):
                response = self.invoke(grant, prompt="AWS-MAIN-PROMPT")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(runtime.calls[0]["modelId"], "us.amazon.nova-lite-v1:0")
        self.assertEqual(runtime.calls[0]["inferenceConfig"], {"maxTokens": 50, "temperature": 0.0})
        call = self.get_ledger(suite_id)["calls"][0]
        self.assertEqual(call["provider_request_id"], "aws-h08-request-1")
        self.assertEqual(call["actual_model_id"], "us.amazon.nova-lite-v1:0")
        self.assertEqual(call["total_tokens"], 15)

    def test_aws_failure_leaves_capability_failed(self):
        suite_id = "08000000-0000-0000-0000-000000000007"
        with patch.object(self.backend, "PROVIDER_MODE", "aws"):
            suite = self.create_suite(suite_id)
            grant = suite["cases"][0]["roles"]["main"]
            error = ClientError(
                {"Error": {"Code": "ThrottlingException", "Message": "slow"}},
                "Converse",
            )
            with patch.object(self.backend, "call_aws", side_effect=error):
                response = self.invoke(grant)
        self.assertEqual(response.status_code, 502)
        capability = next(
            item
            for item in self.get_ledger(suite_id)["capabilities"]
            if item["capability_digest"] == grant["capability_digest"]
        )
        self.assertEqual(capability["status"], "failed")
        self.assertIsNotNone(capability["failed_at"])
        closed = self.client.post(
            f"/v1/h08/suites/{suite_id}/close",
            headers={"Authorization": "Bearer h08-control"},
        )
        self.assertEqual(closed.status_code, 200)
        capability_after_close = next(
            item
            for item in self.get_ledger(suite_id)["capabilities"]
            if item["capability_digest"] == grant["capability_digest"]
        )
        self.assertEqual(capability_after_close["status"], "failed")


if __name__ == "__main__":
    unittest.main()
