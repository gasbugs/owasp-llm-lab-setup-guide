"""Tenant 03 vertical slice security and deployment contracts."""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "llm-security-control-plane"
COMPOSE = ROOT / "examples/security-monitoring/compose.guided.yaml"
os.environ.setdefault("GUIDED_SESSION_SECRET", "unit-session-secret")
os.environ.setdefault("GUIDED_CONTROL_LAB01_TOKEN", "unit-control-lab")
os.environ.setdefault("GUIDED_CONTROL_VERIFIER_TOKEN", "unit-control-verifier")


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

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def post(self, url, *, json, headers):
        self.calls.append({"url": url, "json": json, "headers": headers})
        if url.endswith("/v1/run"):
            return FakeResponse(
                {
                    "execution_id": json["execution_id"],
                    "requested_max_output_tokens": json["requested_max_output_tokens"],
                    "effective_max_output_tokens": json["requested_max_output_tokens"],
                    "policy_digest": "policy-digest",
                    "config_digest": "executor-is-not-trusted",
                    "provider_request_id": "aws-request-1",
                    "model_id": "us.amazon.nova-lite-v1:0",
                    "forwarded_parameters": {
                        "maxTokens": json["requested_max_output_tokens"]
                    },
                    "usage": {"outputTokens": 12},
                    "stop_reason": "end_turn",
                    "response_text": "실제 모델 응답",
                }
            )
        return FakeResponse(
            {
                "lab_id": "01-nova",
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
        self.assertEqual(self.bootstrap["course"]["implemented_hands_on"], ["H01"])
        self.assertEqual(self.bootstrap["course"]["implemented_practices"], [])

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
        self.assertEqual(len(FakeAsyncClient.calls), 3)
        normal_call, risk_call, verifier_call = FakeAsyncClient.calls
        self.assertEqual(normal_call["json"]["requested_max_output_tokens"], 64)
        self.assertEqual(risk_call["json"]["requested_max_output_tokens"], 512)
        self.assertEqual(verifier_call["json"]["suite_kind"], "hands_on")
        self.assertEqual(len(verifier_call["json"]["cases"]), 2)
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
        self.assertEqual(request["prompt"], "현재 정책을 거쳐 실제로 답해 주세요.")
        self.assertEqual(request["requested_max_output_tokens"], 512)
        self.assertEqual(request["scenario"], "chat")

    def test_exploratory_chat_rejects_client_policy_fields(self):
        response = self.client.post(
            "/api/hands-on/H01/chat",
            json={"prompt": "hello", "max_output_tokens": 1, "course_verdict": "PASS"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 422)

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
        self.assertIn("return min(requested_max_tokens, 128)", html)
        self.assertIn("강사와 함께 진행하는 본 실습", html)
        self.assertIn("--env-file llm-security-control-plane/.state/guided-course.env", html)
        self.assertIn('data-theme-choice="light"', html)
        self.assertIn('data-theme-choice="dark"', html)
        self.assertIn('id="chat-form"', html)
        javascript = (CONTROL / "guided-control-center/app.js").read_text(encoding="utf-8")
        self.assertIn("textContent", javascript)
        self.assertNotIn("innerHTML", javascript)
        self.assertIn('matchMedia("(prefers-color-scheme: dark)")', javascript)
        self.assertIn('localStorage.setItem("guided-theme-mode", mode)', javascript)
        self.assertIn('/api/hands-on/H01/chat', javascript)
        stylesheet = (CONTROL / "guided-control-center/app.css").read_text(encoding="utf-8")
        self.assertIn("@media (max-width: 760px)", stylesheet)
        self.assertIn("color-scheme: light dark", stylesheet)
        self.assertIn(':root[data-theme="dark"]', stylesheet)
        self.assertIn("@media (prefers-color-scheme: dark)", stylesheet)
        self.assertIn("prefers-reduced-motion", stylesheet)

    def test_front_proxy_is_the_only_host_port_owner(self):
        compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
        owners = [name for name, service in compose["services"].items() if "ports" in service]
        self.assertEqual(owners, ["guided-front-proxy"])
        self.assertEqual(len(compose["services"]["guided-front-proxy"]["ports"]), 2)
        verifier = compose["services"]["guided-evidence-verifier"]
        serialized = str(verifier)
        self.assertNotIn("/tmp/.aws", serialized)
        self.assertNotIn("docker.sock", serialized)
        self.assertIn("guided-student-app", compose["services"])
        proxy = (CONTROL / "guided-front-proxy/nginx.conf").read_text(encoding="utf-8")
        self.assertIn("proxy_set_header Upgrade $http_upgrade", proxy)
        self.assertIn("proxy_set_header Connection $connection_upgrade", proxy)
        self.assertIn("resolver 127.0.0.11 valid=10s ipv6=off", proxy)
        self.assertIn("server guided-control-center:8000 resolve", proxy)
        self.assertIn("server guided-nemo-ui:8000 resolve", proxy)

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
        self.assertTrue(
            all(tab["hands_on_status"] == "planned" for tab in manifest["tabs"][1:])
        )
        self.assertTrue(
            all(tab["practice_status"] == "planned" for tab in manifest["tabs"])
        )


if __name__ == "__main__":
    unittest.main()
