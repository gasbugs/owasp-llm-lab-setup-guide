"""Tenant 03 vertical slice security and deployment contracts."""

from __future__ import annotations

import importlib.util
import os
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
import httpx
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "llm-security-control-plane"
COMPOSE = ROOT / "examples/security-monitoring/compose.guided.yaml"
os.environ.setdefault("GUIDED_SESSION_SECRET", "unit-session-secret")
os.environ.setdefault("GUIDED_CONTROL_LAB01_TOKEN", "unit-control-lab")
os.environ.setdefault("GUIDED_CONTROL_LAB02_TOKEN", "unit-control-lab02")
os.environ.setdefault("GUIDED_CONTROL_LAB03_TOKEN", "unit-control-lab03")
os.environ.setdefault("GUIDED_CONTROL_LAB04_TOKEN", "unit-control-lab04")
os.environ.setdefault("GUIDED_CONTROL_LAB05_TOKEN", "unit-control-lab05")
os.environ.setdefault("GUIDED_CONTROL_LAB06_TOKEN", "unit-control-lab06")
os.environ.setdefault("GUIDED_CONTROL_LAB07_TOKEN", "unit-control-lab07")
os.environ.setdefault("GUIDED_CONTROL_LAB08_TOKEN", "unit-control-lab08")
os.environ.setdefault("GUIDED_H06_PROVIDER_CONTROL_TOKEN", "unit-h06-provider-control")
os.environ.setdefault("GUIDED_H07_GATEWAY_CONTROL_TOKEN", "unit-h07-gateway-control")
os.environ.setdefault("GUIDED_H08_GATEWAY_CONTROL_TOKEN", "unit-h08-gateway-control")
os.environ.setdefault("GUIDED_CONTROL_H21_TOKEN", "unit-control-h21")
os.environ.setdefault("GUIDED_CONTROL_H22_TOKEN", "unit-control-h22")
os.environ.setdefault("GUIDED_CONTROL_VERIFIER_TOKEN", "unit-control-verifier")
os.environ.setdefault("GUIDED_LAB02_PROVISION_TOKEN", "unit-provision-lab02")
os.environ.setdefault("GUIDED_LAB03_PROVISION_TOKEN", "unit-provision-lab03")
os.environ.setdefault("GUIDED_LAB04_PROVISION_TOKEN", "unit-provision-lab04")


def load_server():
    spec = importlib.util.spec_from_file_location(
        "guided_control_center_server", CONTROL / "guided-control-center/server.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload


class FakeAsyncClient:
    calls: list[dict] = []
    h07_run_status = 200
    h07_run_request_error = False
    h07_close_statuses: list[int] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, url, *, headers):
        self.calls.append({"url": url, "json": None, "headers": headers})
        if "/v1/status/" in url:
            return FakeResponse({"ingestion_job_id": "H03JOB", "status": "COMPLETE"})
        return FakeResponse({"detail": "not found"}, status_code=404)

    async def post(self, url, *, json=None, headers):
        self.calls.append({"url": url, "json": json, "headers": headers})
        if url.endswith("/v1/h08/suites"):
            return FakeResponse(
                {
                    "suite_id": json["suite_id"],
                    "cases": [
                        {
                            "case_id": case_id,
                            "execution_id": f"08000000-0000-0000-0000-00000000000{index}",
                            "roles": {
                                role: {
                                    "model": f"us.amazon.nova-lite-v1:0#h08-{role.replace('_', '-')}",
                                    "capability": f"h08-{case_id}-{role}-" + "x" * 48,
                                    "capability_digest": "e" * 64,
                                }
                                for role in ("self_check_input", "main")
                            },
                        }
                        for index, case_id in enumerate(
                            (
                                "normal-password-reset",
                                "normal-report-injection",
                                "risk-format-marker",
                                "risk-admin-marker",
                            ),
                            1,
                        )
                    ],
                }
            )
        if "/v1/h08/suites/" in url and url.endswith("/close"):
            return FakeResponse(
                {"suite_id": url.rsplit("/", 2)[-2], "closed_at": "2026-09-24T10:00:01+00:00"}
            )
        if url.endswith("/v1/h07/suites"):
            return FakeResponse(
                {
                    "suite_id": json["suite_id"],
                    "cases": [
                        {
                            "case_id": case_id,
                            "execution_id": f"00000000-0000-0000-0000-00000000000{index}",
                            "roles": {
                                role: {
                                    "model": f"us.amazon.nova-lite-v1:0#h07-{role.replace('_', '-')}",
                                    "capability": f"h07-{case_id}-{role}-" + "x" * 48,
                                    "capability_digest": "d" * 64,
                                }
                                for role in ("content_safety", "main")
                            },
                        }
                        for index, case_id in enumerate(("normal-phishing-defense", "risk-phishing-kit"), 1)
                    ],
                }
            )
        if "/v1/h07/suites/" in url and url.endswith("/close"):
            status = self.h07_close_statuses.pop(0) if self.h07_close_statuses else 200
            return FakeResponse(
                {"suite_id": url.rsplit("/", 2)[-2], "closed_at": "2026-09-23T10:00:01+00:00"},
                status_code=status,
            )
        if url.endswith("/v1/suites"):
            return FakeResponse(
                {
                    "suite_id": json["suite_id"],
                    "cases": [
                        {
                            **item,
                            "action_id": None,
                            "capability": f"capability-{item['case_id']}" * 3,
                        }
                        for item in json["executions"]
                    ],
                }
            )
        if url.endswith("/v1/run-suite"):
            return FakeResponse(
                {
                    "suite_id": "88888888-8888-8888-8888-888888888888",
                    "started_at": "2026-09-23T10:00:00+00:00",
                }
            )
        if url.endswith("/v1/chat"):
            if not json["message"] or "model" in json:
                return FakeResponse({"detail": "invalid request"}, status_code=422)
            return FakeResponse(
                {
                    "execution_id": json["execution_id"],
                    "requested_max_output_tokens": json["max_output_tokens"],
                    "effective_max_output_tokens": json["max_output_tokens"],
                    "source_digest": "source-digest",
                    "provider_request_id": "aws-request-1",
                    "model_id": "us.amazon.nova-lite-v1:0",
                    "forwarded_parameters": {
                        "maxTokens": json["max_output_tokens"]
                    },
                    "usage": {"outputTokens": 12},
                    "stop_reason": "end_turn",
                    "response_text": "실제 모델 응답",
                }
            )
        if url.endswith("/v1/h02/provision"):
            return FakeResponse({"status": "READY", "knowledge_base_id": "TESTKB1234"})
        if url.endswith("/v1/h03/provision"):
            return FakeResponse({"status": "READY_FOR_SYNC", "knowledge_base_id": "TESTH03KB"})
        if url.endswith("/v1/h04/provision"):
            return FakeResponse({"status": "READY", "guardrail_id": "TESTH04GR"})
        if url.endswith("/v1/sync"):
            return FakeResponse({"ingestion_job_id": "H03JOB", "status": "STARTING"})
        if url.endswith("/v1/search"):
            return FakeResponse({"retrieval_called": True, "source_uris": ["s3://current"]})
        if url.endswith("/v1/evaluate"):
            return FakeResponse({"evaluation_id": "nemo-topical-unit-evaluation"})
        if url.endswith("/v1/documents"):
            if not json["body"]:
                return FakeResponse({"detail": "invalid request"}, status_code=422)
            return FakeResponse({"execution_id": json["execution_id"]})
        if url.endswith("/v1/run"):
            if "cases" in json:
                if json["cases"] and "content_safety_capability" in json["cases"][0]:
                    if self.h07_run_request_error:
                        raise httpx.ConnectError("H07 learner unavailable", request=httpx.Request("POST", url))
                    if self.h07_run_status != 200:
                        return FakeResponse({"detail": "H07 learner failed"}, status_code=self.h07_run_status)
                return FakeResponse({"suite_id": json["suite_id"], "source_digest": "a" * 64})
            return FakeResponse({"execution_id": json["execution_id"]})
        activity_id = "H22" if "lab-22" in url else "H21" if "lab-21" in url else "H08" if "/h08" in url else "H07" if "/h07" in url else "H06" if "/h06" in url else "H05" if "lab-05" in url else "H04" if "lab-04" in url else "H03" if "lab-03" in url else "H02" if "lab-02" in url else "H01"
        return FakeResponse(
            {
                "lab_id": "02-embedding-kb" if activity_id == "H02" else "01-nova",
                "activity_id": activity_id,
                "execution_id": json["suite_id"],
                "course_verdict": "PASS",
                "verified_by": "guided-evidence-verifier",
                "stage_calls": [
                    {"stage": "bedrock_main", "attempted": True, "outcome": "completed"}
                ],
                "evidence": [{"id": "aws-request-1"}],
                "result": {
                    "model_id": "us.amazon.nova-lite-v1:0",
                    "forwarded_parameters": {"maxTokens": 128},
                    "usage": {"outputTokens": 12},
                    **(
                        {
                            "framework": "nemoguardrails",
                            "framework_version": "0.22.0",
                            "evaluation": {
                                "evaluation_id": "nemo-topical-unit-evaluation",
                                "processed_samples": 4,
                                "intent_errors": 0,
                                "bot_intent_errors": 0,
                                "bot_message_errors": 0,
                            },
                            "risk": {
                                "bot_message": "복구 코드는 공개할 수 없습니다."
                            },
                        }
                        if activity_id == "H05"
                        else {}
                    ),
                    **(
                        {
                            "provider_suite_id": json["suite_id"],
                            "framework": "nemoguardrails",
                            "framework_version": "0.22.0",
                            "provider_calls": [{"action_id": "get_account_balance"}],
                            "effect_count": 0,
                            "balance": 10000,
                        }
                        if activity_id == "H06"
                        else {}
                    ),
                },
            }
        )


class GuidedControlCenterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server()

    def setUp(self):
        self.client = TestClient(self.server.app)
        self.home = self.client.get("/")
        self.bootstrap = self.client.get("/api/bootstrap").json()
        self.headers = {
            "Origin": "http://testserver",
            "X-CSRF-Token": self.bootstrap["csrf_token"],
        }
        FakeAsyncClient.calls.clear()
        FakeAsyncClient.h07_run_status = 200
        FakeAsyncClient.h07_run_request_error = False
        FakeAsyncClient.h07_close_statuses = []

    def test_session_csp_and_browser_token_boundary(self):
        cookie = self.home.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)
        csp = self.home.headers["content-security-policy"]
        self.assertIn("default-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("application_token", self.home.text.lower())
        self.assertNotIn("gateway_token", self.home.text.lower())
        self.assertEqual(self.bootstrap["course"]["tabs"], 13)
        self.assertEqual(self.bootstrap["course"]["hands_on"], 22)
        self.assertEqual(self.bootstrap["course"]["practices"], 13)
        self.assertEqual(self.bootstrap["course"]["implemented_hands_on"], ["H01", "H02", "H03", "H04", "H05", "H06", "H07", "H08", "H21", "H22"])
        self.assertEqual(self.bootstrap["course"]["implemented_practices"], [])
        h05 = next(
            item
            for item in self.bootstrap["learner_apps"]
            if item["hands_on_id"] == "H05"
        )
        self.assertEqual(h05["service"], "guided-h05-nemo-dialog")
        self.assertTrue(h05["source_path"].endswith("h05-nemo-dialog/config/flows.co"))
        h06 = next(
            item
            for item in self.bootstrap["learner_apps"]
            if item["hands_on_id"] == "H06"
        )
        self.assertEqual(h06["service"], "guided-h06-nemo-action")
        self.assertTrue(h06["source_path"].endswith("h06-nemo-action/actions.py"))
        h08 = next(
            item
            for item in self.bootstrap["learner_apps"]
            if item["hands_on_id"] == "H08"
        )
        self.assertEqual(h08["service"], "guided-h08-self-check-input")
        self.assertTrue(h08["source_path"].endswith("h08-self-check-input/config/prompts.yml"))

    def test_origin_csrf_and_client_verdict_are_rejected(self):
        self.assertEqual(self.client.post("/api/hands-on/H01/verify").status_code, 403)
        self.assertEqual(
            self.client.post(
                "/api/hands-on/H01/verify",
                headers={**self.headers, "Origin": "https://evil.example"},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/hands-on/H01/verify",
                json={"course_verdict": "PASS", "max_output_tokens": 1},
                headers=self.headers,
            ).status_code,
            422,
        )

    def test_control_center_creates_execution_and_uses_verifier_result(self):
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/hands-on/H01/verify",
                headers=self.headers,
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "PASS")
        self.assertEqual(len(FakeAsyncClient.calls), 5)
        normal_call, risk_call, invalid_call, override_call, verifier_call = FakeAsyncClient.calls
        self.assertEqual(normal_call["json"]["max_output_tokens"], 64)
        self.assertEqual(risk_call["json"]["max_output_tokens"], 512)
        self.assertEqual(invalid_call["json"]["message"], "")
        self.assertEqual(override_call["json"]["model"], "attacker-selected-model")
        self.assertEqual(verifier_call["json"]["suite_kind"], "hands_on")
        self.assertEqual(len(verifier_call["json"]["cases"]), 4)
        self.assertNotIn("course_verdict", verifier_call["json"])
        self.assertNotIn("unit-control-lab", response.text)
        self.assertNotIn("unit-control-verifier", response.text)

    def test_exploratory_chat_uses_current_learner_app_without_grading(self):
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/hands-on/H01/chat",
                json={"prompt": "현재 정책을 거쳐 실제로 답해 주세요."},
                headers=self.headers,
            )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["graded"])
        self.assertEqual(payload["execution_kind"], "exploratory_chat")
        self.assertEqual(payload["result"]["response_text"], "실제 모델 응답")
        self.assertEqual(len(FakeAsyncClient.calls), 1)
        request = FakeAsyncClient.calls[0]["json"]
        self.assertEqual(request["message"], "현재 정책을 거쳐 실제로 답해 주세요.")
        self.assertEqual(request["max_output_tokens"], 512)
        self.assertEqual(request["scenario"], "chat")

    def test_exploratory_chat_rejects_client_policy_fields(self):
        response = self.client.post(
            "/api/hands-on/H01/chat",
            json={"prompt": "hello", "max_output_tokens": 1, "course_verdict": "PASS"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 422)

    def test_h02_suite_uses_server_owned_document_cases(self):
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/hands-on/H02/verify",
                headers=self.headers,
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["activity_id"], "H02")
        self.assertEqual(len(FakeAsyncClient.calls), 4)
        normal, risk, invalid, verifier = FakeAsyncClient.calls
        self.assertNotIn("object_key", normal["json"])
        self.assertTrue(risk["json"]["object_key"].startswith("h02/untrusted/"))
        self.assertEqual(invalid["json"]["body"], "")
        self.assertEqual(len(verifier["json"]["cases"]), 3)
        self.assertNotIn("course_verdict", verifier["json"])

    def test_h02_provisioning_body_is_server_owned(self):
        rejected = self.client.post(
            "/api/hands-on/H02/provision",
            json={"bucket": "attacker-bucket"},
            headers=self.headers,
        )
        self.assertEqual(rejected.status_code, 422)
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/hands-on/H02/provision", headers=self.headers
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["activity_id"], "H02")

    def test_h03_suite_uses_current_server_owned_job(self):
        rejected = self.client.post(
            "/api/hands-on/H03/verify",
            json={"job_id": "attacker-job", "course_verdict": "PASS"},
            headers=self.headers,
        )
        self.assertEqual(rejected.status_code, 422)
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/hands-on/H03/verify", headers=self.headers
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["activity_id"], "H03")
        sync_call = next(item for item in FakeAsyncClient.calls if item["url"].endswith("/v1/sync"))
        verifier_call = next(item for item in FakeAsyncClient.calls if "lab-03" in item["url"])
        self.assertNotIn("ingestion_job_id", sync_call["json"])
        self.assertNotIn("course_verdict", verifier_call["json"])

    def test_h03_provisioning_body_is_server_owned(self):
        rejected = self.client.post(
            "/api/hands-on/H03/provision",
            json={"knowledge_base_id": "attacker-kb"},
            headers=self.headers,
        )
        self.assertEqual(rejected.status_code, 422)
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/hands-on/H03/provision", headers=self.headers
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["activity_id"], "H03")

    def test_h04_suite_and_provisioning_inputs_are_server_owned(self):
        rejected = self.client.post(
            "/api/hands-on/H04/verify",
            json={"guardrail_id": "attacker", "course_verdict": "PASS"},
            headers=self.headers,
        )
        self.assertEqual(rejected.status_code, 422)
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/hands-on/H04/verify", headers=self.headers
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["activity_id"], "H04")
        run_calls = [item for item in FakeAsyncClient.calls if item["url"].endswith("/v1/run")]
        self.assertEqual(
            [item["json"]["case_id"] for item in run_calls],
            ["apply-normal", "apply-risk", "converse-normal", "converse-risk"],
        )
        self.assertTrue(all("guardrail_id" not in item["json"] for item in run_calls))
        verifier_call = next(item for item in FakeAsyncClient.calls if "lab-04" in item["url"])
        self.assertNotIn("course_verdict", verifier_call["json"])

        FakeAsyncClient.calls.clear()
        rejected = self.client.post(
            "/api/hands-on/H04/provision",
            json={"policy": {"outputEnabled": False}},
            headers=self.headers,
        )
        self.assertEqual(rejected.status_code, 422)
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            provisioned = self.client.post(
                "/api/hands-on/H04/provision", headers=self.headers
            )
        self.assertEqual(provisioned.status_code, 200)
        self.assertEqual(provisioned.json()["activity_id"], "H04")

    def test_h05_suite_and_evaluation_inputs_are_server_owned(self):
        rejected = self.client.post(
            "/api/hands-on/H05/verify",
            json={"prompt": "attacker input", "course_verdict": "PASS"},
            headers=self.headers,
        )
        self.assertEqual(rejected.status_code, 422)

        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/hands-on/H05/verify", headers=self.headers
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["activity_id"], "H05")
        run_calls = [
            item for item in FakeAsyncClient.calls if item["url"].endswith("/v1/run")
        ]
        self.assertEqual(
            [item["json"]["case_id"] for item in run_calls],
            ["contact-exact", "contact-paraphrase", "recovery-risk", "unsupported"],
        )
        evaluation_call = next(
            item for item in FakeAsyncClient.calls if item["url"].endswith("/v1/evaluate")
        )
        verifier_call = next(
            item for item in FakeAsyncClient.calls if "lab-05" in item["url"]
        )
        self.assertEqual(
            evaluation_call["json"]["suite_id"], verifier_call["json"]["suite_id"]
        )
        self.assertEqual(
            verifier_call["json"]["evaluation_id"],
            "nemo-topical-unit-evaluation",
        )
        self.assertEqual(len(verifier_call["json"]["cases"]), 4)
        self.assertNotIn("course_verdict", verifier_call["json"])
        self.assertNotIn("prompt", verifier_call["json"])
        self.assertNotIn("unit-control-lab05", response.text)

    def test_h06_suite_actions_and_verdict_are_server_owned(self):
        rejected = self.client.post(
            "/api/hands-on/H06/verify",
            json={
                "case_id": "balance-read",
                "action_id": "get_account_balance",
                "course_verdict": "PASS",
            },
            headers=self.headers,
        )
        self.assertEqual(rejected.status_code, 422)

        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/hands-on/H06/verify", headers=self.headers
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["activity_id"], "H06")
        provider_call = next(
            item for item in FakeAsyncClient.calls if item["url"].endswith("/v1/suites")
        )
        self.assertEqual(
            [item["case_id"] for item in provider_call["json"]["executions"]],
            ["balance-read", "transfer-explicit", "transfer-prefixed", "unsupported"],
        )
        self.assertEqual(
            [item.get("action_id") for item in provider_call["json"]["executions"]],
            [None, None, None, None],
        )
        learner_call = next(
            item
            for item in FakeAsyncClient.calls
            if item["url"].endswith("/v1/run") and "cases" in item["json"]
        )
        self.assertEqual(len(learner_call["json"]["cases"]), 4)
        self.assertTrue(
            all("action_id" not in item for item in learner_call["json"]["cases"])
        )
        verifier_call = next(
            item for item in FakeAsyncClient.calls if item["url"].endswith("/v1/verify/h06")
        )
        self.assertEqual(verifier_call["json"]["suite_id"], provider_call["json"]["suite_id"])
        self.assertNotIn("course_verdict", verifier_call["json"])
        self.assertNotIn("capabilities", verifier_call["json"])
        self.assertNotIn("unit-h06-provider-control", response.text)

    def test_h07_closes_gateway_suite_before_read_only_verification(self):
        rejected = self.client.post(
            "/api/hands-on/H07/verify",
            json={"course_verdict": "PASS", "model": "attacker-model"},
            headers=self.headers,
        )
        self.assertEqual(rejected.status_code, 422)

        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/hands-on/H07/verify", headers=self.headers
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["activity_id"], "H07")
        urls = [item["url"] for item in FakeAsyncClient.calls]
        prepare_index = next(index for index, url in enumerate(urls) if url.endswith("/v1/h07/suites"))
        learner_index = next(index for index, url in enumerate(urls) if url.endswith("/v1/run"))
        close_index = next(index for index, url in enumerate(urls) if url.endswith("/close"))
        verify_index = next(index for index, url in enumerate(urls) if url.endswith("/v1/verify/h07"))
        self.assertLess(prepare_index, learner_index)
        self.assertLess(learner_index, close_index)
        self.assertLess(close_index, verify_index)
        learner = FakeAsyncClient.calls[learner_index]["json"]
        self.assertEqual(
            [item["case_id"] for item in learner["cases"]],
            ["normal-phishing-defense", "risk-phishing-kit"],
        )
        self.assertTrue(all(set(item) == {"case_id", "execution_id", "content_safety_capability", "main_capability"} for item in learner["cases"]))
        verifier = FakeAsyncClient.calls[verify_index]["json"]
        self.assertEqual(set(verifier), {"suite_id", "started_at"})
        self.assertNotIn("course_verdict", verifier)
        self.assertNotIn("unit-h07-gateway-control", response.text)

    def test_h08_empty_request_closes_suite_before_read_only_verification(self):
        rejected = self.client.post(
            "/api/hands-on/H08/verify",
            json={"course_verdict": "PASS", "prompt": "browser-owned"},
            headers=self.headers,
        )
        self.assertEqual(rejected.status_code, 422)

        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/hands-on/H08/verify", headers=self.headers
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["activity_id"], "H08")
        urls = [item["url"] for item in FakeAsyncClient.calls]
        prepare_index = next(
            index for index, url in enumerate(urls) if url.endswith("/v1/h08/suites")
        )
        learner_index = next(
            index
            for index, item in enumerate(FakeAsyncClient.calls)
            if item["url"].endswith("/v1/run")
            and item["json"]["cases"]
            and "self_check_input_capability" in item["json"]["cases"][0]
        )
        close_index = next(
            index
            for index, url in enumerate(urls)
            if "/v1/h08/suites/" in url and url.endswith("/close")
        )
        verify_index = next(
            index for index, url in enumerate(urls) if url.endswith("/v1/verify/h08")
        )
        self.assertLess(prepare_index, learner_index)
        self.assertLess(learner_index, close_index)
        self.assertLess(close_index, verify_index)
        learner = FakeAsyncClient.calls[learner_index]["json"]
        self.assertEqual(
            [item["case_id"] for item in learner["cases"]],
            [
                "normal-password-reset",
                "normal-report-injection",
                "risk-format-marker",
                "risk-admin-marker",
            ],
        )
        self.assertTrue(
            all(
                set(item)
                == {
                    "case_id",
                    "execution_id",
                    "self_check_input_capability",
                    "main_capability",
                }
                for item in learner["cases"]
            )
        )
        verifier = FakeAsyncClient.calls[verify_index]["json"]
        self.assertEqual(set(verifier), {"suite_id", "started_at"})
        self.assertNotIn("course_verdict", verifier)
        self.assertNotIn("unit-h08-gateway-control", response.text)

    def test_h07_learner_failure_and_request_error_close_issued_capabilities(self):
        for request_error in (False, True):
            with self.subTest(request_error=request_error):
                FakeAsyncClient.calls.clear()
                FakeAsyncClient.h07_run_status = 503
                FakeAsyncClient.h07_run_request_error = request_error
                with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
                    response = self.client.post("/api/hands-on/H07/verify", headers=self.headers)
                self.assertEqual(response.status_code, 502)
                self.assertTrue(response.json()["detail"]["downstream_called"])
                urls = [item["url"] for item in FakeAsyncClient.calls]
                self.assertTrue(any(url.endswith("/v1/h07/suites") for url in urls))
                self.assertTrue(any(url.endswith("/v1/run") for url in urls))
                self.assertTrue(any(url.endswith("/close") for url in urls))

    def test_h07_close_retries_409_and_reports_called_downstream_on_failure(self):
        FakeAsyncClient.h07_close_statuses = [409, 409, 409, 409, 409, 409]
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient), patch.object(
            self.server.asyncio, "sleep", return_value=None
        ):
            response = self.client.post("/api/hands-on/H07/verify", headers=self.headers)
        self.assertEqual(response.status_code, 502)
        self.assertTrue(response.json()["detail"]["downstream_called"])
        close_calls = [item for item in FakeAsyncClient.calls if item["url"].endswith("/close")]
        self.assertEqual(len(close_calls), 6)
        self.assertFalse(any(item["url"].endswith("/v1/verify/h07") for item in FakeAsyncClient.calls))

    def test_h22_suite_is_server_owned_and_uses_verifier(self):
        rejected = self.client.post(
            "/api/hands-on/H22/verify",
            json={"course_verdict": "PASS", "approval": True},
            headers=self.headers,
        )
        self.assertEqual(rejected.status_code, 422)
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/hands-on/H22/verify", headers=self.headers
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["activity_id"], "H22")
        run_call, verifier_call = FakeAsyncClient.calls
        self.assertIsNone(run_call["json"])
        self.assertEqual(
            verifier_call["json"]["suite_id"],
            "88888888-8888-8888-8888-888888888888",
        )
        self.assertNotIn("course_verdict", verifier_call["json"])

    def test_h21_suite_is_server_owned_and_uses_verifier(self):
        rejected = self.client.post(
            "/api/hands-on/H21/verify",
            json={"model": "attacker-selected-model", "course_verdict": "PASS"},
            headers=self.headers,
        )
        self.assertEqual(rejected.status_code, 422)
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/hands-on/H21/verify", headers=self.headers
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["activity_id"], "H21")
        run_call, verifier_call = FakeAsyncClient.calls
        self.assertIsNone(run_call["json"])
        self.assertNotIn("course_verdict", verifier_call["json"])

    def test_unknown_host_is_rejected(self):
        response = self.client.get("/", headers={"Host": "attacker.example"})
        self.assertEqual(response.status_code, 421)

    def test_session_store_evicts_idle_sessions_at_the_limit(self):
        with patch.object(self.server, "MAX_SESSIONS", 2):
            self.client.get("/")
            self.client.get("/")
        self.assertEqual(len(self.server.SESSIONS), 2)
        self.assertFalse(self.server.ACTIVE_SESSIONS)

    def test_rendering_uses_text_nodes_only(self):
        html = (CONTROL / "guided-control-center/index.html").read_text(encoding="utf-8")
        self.assertIn("effective_max_tokens = min(request.max_output_tokens, 128)", html)
        self.assertIn('boto3.client("bedrock-runtime"', html)
        self.assertNotIn("강사와 함께", html)
        self.assertNotIn("비용 안내", html)
        self.assertIn("--env-file llm-security-control-plane/.state/guided-course.env", html)
        self.assertIn('data-theme-choice="light"', html)
        self.assertIn('data-theme-choice="dark"', html)
        self.assertIn('id="chat-form"', html)
        action_help = {
            "chat-send": "chat-send-help",
            "preflight": "preflight-help",
            "verify": "verify-help",
            "h02-provision": "h02-provision-help",
            "h02-verify": "h02-verify-help",
            "h03-provision": "h03-provision-help",
            "h03-verify": "h03-verify-help",
            "h04-provision": "h04-provision-help",
            "h04-verify": "h04-verify-help",
            "h05-verify": "h05-verify-help",
            "h06-verify": "h06-verify-help",
            "h07-verify": "h07-verify-help",
            "h08-verify": "h08-verify-help",
            "h21-verify": "h21-verify-help",
            "h22-verify": "h22-verify-help",
        }
        for button_id, tooltip_id in action_help.items():
            self.assertIn(f'id="{button_id}"', html)
            self.assertIn(f'aria-describedby="{tooltip_id}"', html)
            self.assertIn(f'id="{tooltip_id}" class="action-tooltip" role="tooltip"', html)
        self.assertIn("AWS 자격 증명과 모델 연결", html)
        self.assertIn("S3 Vector Index", html)
        self.assertIn("복구 코드는 공개할 수 없습니다.", html)
        self.assertIn("NeMo Topical 평가", html)
        self.assertIn("Return exactly Yes when the request must be blocked.", html)
        self.assertIn("다른 공격 문장까지 모두 막는다는 뜻은 아닙니다", html)
        self.assertIn("Token 제한 코드가 맞다는 뜻은 아닙니다", html)
        javascript = (CONTROL / "guided-control-center/app.js").read_text(encoding="utf-8")
        self.assertIn("textContent", javascript)
        self.assertNotIn("innerHTML", javascript)
        self.assertIn('matchMedia("(prefers-color-scheme: dark)")', javascript)
        self.assertIn('localStorage.setItem("guided-theme-mode", mode)', javascript)
        self.assertIn('/api/hands-on/H01/chat', javascript)
        self.assertIn('querySelectorAll(".help-trigger")', javascript)
        self.assertIn('setAttribute("aria-expanded", String(open))', javascript)
        self.assertIn('event.key === "Escape"', javascript)
        stylesheet = (CONTROL / "guided-control-center/app.css").read_text(encoding="utf-8")
        self.assertIn("@media (max-width: 760px)", stylesheet)
        self.assertIn("color-scheme: light dark", stylesheet)
        self.assertIn(':root[data-theme="dark"]', stylesheet)
        self.assertIn("@media (prefers-color-scheme: dark)", stylesheet)
        self.assertIn("prefers-reduced-motion", stylesheet)
        self.assertIn(".action-control.tip-open .action-tooltip", stylesheet)
        self.assertIn(
            ".actions:not(.single) > .action-control:last-child .action-tooltip",
            stylesheet,
        )

    def test_rendering_only_updates_existing_dom_ids(self):
        html = (CONTROL / "guided-control-center/index.html").read_text(encoding="utf-8")
        javascript = (CONTROL / "guided-control-center/app.js").read_text(encoding="utf-8")
        html_ids = set(re.findall(r'\bid="([^"]+)"', html))
        updated_ids = set(re.findall(r'setText\("([^"]+)"', javascript))
        self.assertFalse(updated_ids - html_ids, updated_ids - html_ids)

    def test_containerfile_makes_source_readable_to_non_root_runtime(self):
        containerfile = (CONTROL / "guided-control-center/Containerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "COPY --chmod=0444 guided-control-center/requirements.txt",
            containerfile,
        )
        self.assertIn(
            "COPY --chmod=0444 guided-control-center/server.py",
            containerfile,
        )
        self.assertIn("USER 65532:65532", containerfile)

    def test_front_proxy_is_the_only_host_port_owner(self):
        compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
        owners = [name for name, service in compose["services"].items() if "ports" in service]
        self.assertEqual(owners, ["guided-front-proxy"])
        self.assertEqual(len(compose["services"]["guided-front-proxy"]["ports"]), 2)
        verifier = compose["services"]["guided-evidence-verifier"]
        serialized = str(verifier)
        self.assertNotIn("/tmp/.aws", serialized)
        self.assertNotIn("docker.sock", serialized)
        self.assertIn("guided-h01-gateway", compose["services"])
        self.assertIn("guided-h02-document-app", compose["services"])
        self.assertIn("guided-h03-sync-app", compose["services"])
        self.assertIn("guided-h08-self-check-input", compose["services"])
        self.assertIn("guided-h21-host", compose["services"])
        self.assertIn("guided-h21-provider", compose["services"])
        self.assertIn("guided-h21-trusted-mcp", compose["services"])
        self.assertIn("guided-h21-untrusted-mcp", compose["services"])
        self.assertIn("guided-h22-mcp-server", compose["services"])
        self.assertIn("guided-h22-host", compose["services"])
        self.assertIn("guided-bedrock-gateway", compose["services"])
        h08 = compose["services"]["guided-h08-self-check-input"]
        self.assertEqual(h08["environment"]["GUIDED_H08_DATABASE"], "/state/receipts.sqlite3")
        self.assertIn("guided-h08-receipts:/state:rw", h08["volumes"])
        self.assertNotIn("/tmp/.aws", str(h08))
        control_environment = compose["services"]["guided-control-center"]["environment"]
        verifier_environment = compose["services"]["guided-evidence-verifier"]["environment"]
        gateway_environment = compose["services"]["guided-bedrock-gateway"]["environment"]
        self.assertEqual(control_environment["GUIDED_LAB08_URL"], "http://guided-h08-self-check-input:8000")
        self.assertIn("GUIDED_CONTROL_LAB08_TOKEN", control_environment)
        self.assertIn("GUIDED_VERIFIER_LAB08_TOKEN", verifier_environment)
        self.assertIn("GUIDED_H08_CAPABILITY_SECRET", gateway_environment)
        readme = (CONTROL / "README.md").read_text(encoding="utf-8")
        for name in (
            "GUIDED_CONTROL_LAB08_TOKEN",
            "GUIDED_VERIFIER_LAB08_TOKEN",
            "GUIDED_H08_GATEWAY_CONTROL_TOKEN",
            "GUIDED_H08_GATEWAY_VERIFIER_TOKEN",
            "GUIDED_H08_CAPABILITY_SECRET",
        ):
            self.assertIn(f"{name}=$(openssl rand -hex 32)", readme)
        proxy = (CONTROL / "guided-front-proxy/nginx.conf").read_text(encoding="utf-8")
        self.assertIn("proxy_set_header Upgrade $http_upgrade", proxy)
        self.assertIn("proxy_set_header Connection $connection_upgrade", proxy)
        self.assertIn("resolver 127.0.0.11 valid=10s ipv6=off", proxy)
        self.assertIn("server guided-control-center:8000 resolve", proxy)
        self.assertIn("server guided-nemo-ui:8000 resolve", proxy)

    def test_h01_is_a_real_gateway_and_next_labs_keep_a_provided_baseline(self):
        source = (CONTROL / "guided-labs/h01-bedrock-gateway/server.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('@app.post("/v1/chat")', source)
        self.assertIn('boto3.client("bedrock-runtime", region_name=REGION).converse(', source)
        self.assertIn('model_config = ConfigDict(extra="forbid")', source)
        self.assertIn("effective_max_tokens = request.max_output_tokens", source)

        compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
        learner = compose["services"]["guided-h01-gateway"]
        baseline = compose["services"]["guided-bedrock-gateway"]
        self.assertNotEqual(learner["image"], baseline["image"])
        self.assertNotEqual(learner["container_name"], baseline["container_name"])
        self.assertIn("/tmp/.aws:ro", str(learner["volumes"]))
        self.assertNotIn("guided-h01-gateway", str(baseline))

    def test_manifest_has_13_tabs_and_22_unique_activities(self):
        manifest = yaml.safe_load(
            (CONTROL / "guided-labs/manifest.yaml").read_text(encoding="utf-8")
        )
        hands_on = [str(item) for tab in manifest["tabs"] for item in tab["hands_on"]]
        practices = [str(tab["practice"]) for tab in manifest["tabs"]]
        self.assertEqual(len(manifest["tabs"]), 13)
        self.assertEqual(len(hands_on), 22)
        self.assertEqual(len(set(hands_on)), 22)
        self.assertEqual(len(practices), 13)
        self.assertEqual(len(set(practices)), 13)
        self.assertEqual(hands_on[0], "H01")
        self.assertEqual(practices[0], "P01")
        self.assertEqual(manifest["tabs"][0]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][1]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][1]["implemented_hands_on"], ["H02", "H03"])
        self.assertEqual(manifest["tabs"][2]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][2]["implemented_hands_on"], ["H04"])
        self.assertEqual(manifest["tabs"][3]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][3]["implemented_hands_on"], ["H05", "H06"])
        self.assertEqual(manifest["tabs"][4]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][4]["implemented_hands_on"], ["H07", "H08"])
        self.assertEqual(
            manifest["hands_on_H08"]["source_path"],
            "guided-labs/h08-self-check-input/config/prompts.yml",
        )
        self.assertEqual(
            manifest["hands_on_H08"]["control_endpoint"],
            "/api/hands-on/H08/verify",
        )
        self.assertTrue(all(tab["hands_on_status"] == "planned" for tab in manifest["tabs"][5:12]))
        self.assertEqual(manifest["tabs"][12]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][12]["implemented_hands_on"], ["H21", "H22"])
        self.assertTrue(
            all(tab["practice_status"] == "planned" for tab in manifest["tabs"])
        )


if __name__ == "__main__":
    unittest.main()
