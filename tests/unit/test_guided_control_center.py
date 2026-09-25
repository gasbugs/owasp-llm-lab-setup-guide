"""Tenant 03 vertical slice security and deployment contracts."""

from __future__ import annotations

import importlib.util
import html as html_module
import json
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
os.environ.setdefault("GUIDED_CONTROL_LAB09_TOKEN", "unit-control-lab09")
for number in range(10, 17):
    os.environ.setdefault(f"GUIDED_CONTROL_LAB{number}_TOKEN", f"unit-control-lab{number}")
os.environ.setdefault("GUIDED_CONTROL_OBSERVABILITY_TOKEN", "unit-control-observability")
os.environ.setdefault("GUIDED_CONTROL_H18_TOKEN", "unit-control-h18")
os.environ.setdefault("GUIDED_CONTROL_H19_TOKEN", "unit-control-h19")
os.environ.setdefault("GUIDED_CONTROL_H17_TOKEN", "unit-control-h17")
os.environ.setdefault("GUIDED_H06_PROVIDER_CONTROL_TOKEN", "unit-h06-provider-control")
os.environ.setdefault("GUIDED_H07_GATEWAY_CONTROL_TOKEN", "unit-h07-gateway-control")
os.environ.setdefault("GUIDED_H08_GATEWAY_CONTROL_TOKEN", "unit-h08-gateway-control")
os.environ.setdefault("GUIDED_H09_SINK_CONTROL_TOKEN", "unit-h09-sink-control")
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
        if "guided-h09-delivery-sink" in url and url.endswith("/close"):
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
            message, tokens = json.get("message"), json.get("max_output_tokens")
            if not isinstance(message, str) or not message.strip() or len(message) > 4000 or type(tokens) is not int or not 1 <= tokens <= 512 or "model" in json:
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
        if url.endswith("/v1/p03/resources/prepare"):
            return FakeResponse({"practice_id": "P03", "operation_id": json["operation_id"], "state": "ready",
                                 "resources": {"provider_mode": "aws"}, "evidence": {"document": {}}})
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
            if "guided-h02-document-app" in url or "guided-h03-sync-app" in url:
                return FakeResponse({"suite_id": json["suite_id"]})
            if "cases" in json:
                if json["cases"] and "content_safety_capability" in json["cases"][0]:
                    if self.h07_run_request_error:
                        raise httpx.ConnectError("H07 learner unavailable", request=httpx.Request("POST", url))
                    if self.h07_run_status != 200:
                        return FakeResponse({"detail": "H07 learner failed"}, status_code=self.h07_run_status)
                return FakeResponse({"suite_id": json["suite_id"], "source_digest": "a" * 64})
            return FakeResponse({"execution_id": json["execution_id"]})
        activity_id = "P03" if "/verify/p03" in url else "P02" if "/verify/p02" in url else "H22" if "lab-22" in url else "H21" if "lab-21" in url else "H09" if "/h09" in url else "H08" if "/h08" in url else "H07" if "/h07" in url else "H06" if "/h06" in url else "H05" if "lab-05" in url else "H04" if "lab-04" in url else "H03" if "lab-03" in url else "H02" if "lab-02" in url else "H01"
        return FakeResponse(
            {
                "lab_id": "02-embedding-kb" if activity_id == "H02" else "01-nova",
                "activity_id": activity_id,
                "execution_id": json["suite_id"],
                **({"contract_version": "p02-document-v1", "task_completed": True,
                    "security_verdict": "PASS"} if activity_id == "P02" else {}),
                **({"contract_version": "p03-search-v1", "task_completed": True,
                    "security_verdict": "PASS"} if activity_id == "P03" else {}),
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
        self.assertEqual(self.bootstrap["course"]["implemented_hands_on"], [f"H{number:02d}" for number in range(1, 23)])
        self.assertEqual(self.bootstrap['workspace'], 'practice')
        p02 = next(item for item in self.bootstrap["learner_apps"] if item["hands_on_id"] == "H02")
        self.assertEqual(p02["source_path"], "llm-security-control-plane/guided-labs/h02-document-ingestion/learner.py")
        self.assertEqual(self.bootstrap['course']['practices'], 22)
        self.assertEqual(self.bootstrap['course']['practice_ids'], [f'P{n:02d}' for n in range(1, 23)])
        self.assertEqual(self.bootstrap['course']['execution_ids'], {f'P{n:02d}': f'H{n:02d}' for n in range(1, 23)})
        for item in self.bootstrap['learner_apps']:
            self.assertEqual(item['practice_id'], 'P' + item['hands_on_id'][1:])
            self.assertEqual(item['internal_activity_id'], item['hands_on_id'])
        self.assertNotIn("implemented_practices", self.bootstrap["course"])
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
        h09 = next(
            item
            for item in self.bootstrap["learner_apps"]
            if item["hands_on_id"] == "H09"
        )
        self.assertEqual(h09["service"], "guided-h09-presidio-redaction")
        self.assertTrue(h09["source_path"].endswith("h09-presidio-redaction/policy.py"))

    def test_common_pages_and_readiness_do_not_contact_learner_services(self):
        with patch.object(self.server.httpx, "AsyncClient", side_effect=AssertionError("unexpected downstream connection")):
            for path in ("/", "/livez", "/readyz", "/api/bootstrap", "/app.css", "/app.js"):
                with self.subTest(path=path):
                    self.assertEqual(self.client.get(path).status_code, 200)

    def test_official_ui_defaults_use_tenant03_ports(self):
        urls = {item["id"]: item.get("browser_url") for item in self.bootstrap["official_uis"]}
        self.assertEqual(urls["nemo"], "http://127.0.0.1:28192")
        self.assertEqual(urls["promptfoo"], "http://127.0.0.1:25500")
        self.assertEqual(urls["pyrit"], "http://127.0.0.1:28098")
        self.assertEqual(urls["grafana"], "http://127.0.0.1:23001/explore")
        self.assertEqual(urls["p20-grafana"], "http://127.0.0.1:23002/d/guided-p20")

    def test_practice_aliases_cover_exactly_the_existing_handlers(self):
        routes = {route.path: route for route in self.server.app.routes}
        legacy = {path: route for path, route in routes.items()
                  if path.startswith("/api/hands-on/H")}
        expected = {f"/api/practice/P{number:02d}/verify" for number in range(1, 23)}
        expected.update(f"/api/practice/P{number:02d}/provision" for number in (2, 3, 4))
        expected.add("/api/practice/P01/chat")
        actual = {path for path in routes if path.startswith("/api/practice/")}
        self.assertEqual(actual, expected)
        self.assertEqual(len(legacy), len(expected))
        for path, route in legacy.items():
            alias = path.replace("/api/hands-on/H", "/api/practice/P", 1)
            with self.subTest(alias=alias):
                if alias.startswith('/api/practice/P04/'):
                    self.assertIsNot(routes[alias].endpoint, route.endpoint)
                else:
                    self.assertIs(routes[alias].endpoint, route.endpoint)
                self.assertEqual(routes[alias].methods, {"POST"})

    def test_all_practice_routes_reject_missing_csrf_and_browser_verdicts(self):
        anonymous = TestClient(self.server.app)
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            for route in self.server.app.routes:
                if not route.path.startswith("/api/practice/"):
                    continue
                with self.subTest(path=route.path):
                    self.assertEqual(anonymous.post(route.path, headers=self.headers).status_code, 401)
                    self.assertEqual(self.client.post(route.path).status_code, 403)
                    self.assertEqual(self.client.post(
                        route.path, headers={**self.headers, "Origin": "https://evil.example"}
                    ).status_code, 403)
                    self.assertEqual(self.client.post(
                        route.path, headers=self.headers,
                        json={"task_completed": True, "security_verdict": "PASS"}
                    ).status_code, 422)
        self.assertEqual(FakeAsyncClient.calls, [])

    def test_unknown_practice_ids_do_not_fall_back_to_another_activity(self):
        for activity in ("P00", "P23", "P1", "H01", "p01"):
            with self.subTest(activity=activity):
                response = self.client.post(f"/api/practice/{activity}/verify", headers=self.headers)
                self.assertEqual(response.status_code, 404)

    def test_practice_alias_preserves_verdict_with_public_identity(self):
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post("/api/practice/P01/verify", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "PASS")
        self.assertEqual(response.json()["activity_id"], "P01")
        self.assertEqual(response.json()["internal_activity_id"], "H01")
        self.assertEqual(len(FakeAsyncClient.calls), 22)
        self.assertEqual(FakeAsyncClient.calls[-1]["json"]["suite_kind"], "hands_on")
        self.assertNotIn("unit-control-verifier", response.text)

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
        self.assertEqual(len(FakeAsyncClient.calls), 22)
        normal_call, risk_call = FakeAsyncClient.calls[:2]
        invalid_call, override_call, verifier_call = FakeAsyncClient.calls[7], FakeAsyncClient.calls[20], FakeAsyncClient.calls[-1]
        self.assertEqual(normal_call["json"]["max_output_tokens"], 64)
        self.assertEqual(risk_call["json"]["max_output_tokens"], 512)
        self.assertEqual(invalid_call["json"]["message"], "")
        self.assertEqual(override_call["json"]["model"], "client-selected-model")
        self.assertEqual(verifier_call["json"]["suite_kind"], "hands_on")
        self.assertEqual(len(verifier_call["json"]["cases"]), 21)
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
        self.assertEqual(response.json()["activity_id"], "P02")
        self.assertEqual(len(FakeAsyncClient.calls), 2)
        runner, verifier = FakeAsyncClient.calls
        self.assertTrue(runner["url"].endswith("/v1/run"))
        self.assertEqual(set(runner["json"]), {"suite_id"})
        self.assertEqual(runner["json"], verifier["json"])
        self.assertTrue(verifier["url"].endswith("/v1/verify/p02"))
        self.assertNotIn("course_verdict", verifier["json"])

    def test_p02_verifier_errors_and_mismatched_results_are_incomplete(self):
        for fault in ("http", "network", "shape", "suite", "activity", "contract", "verdict", "completion"):
            class FaultClient(FakeAsyncClient):
                async def post(inner, url, **kwargs):
                    response = await super().post(url, **kwargs)
                    if not url.endswith("/v1/verify/p02"):
                        return response
                    if fault == "http":
                        return FakeResponse({}, status_code=503)
                    if fault == "network":
                        raise httpx.ConnectError("unavailable")
                    if fault == "shape":
                        return FakeResponse([])
                    changes = {"suite": {"execution_id": "another-run"},
                               "activity": {"activity_id": "P01"},
                               "contract": {"contract_version": "old"},
                               "verdict": {"security_verdict": "ERR"},
                               "completion": {"task_completed": "true"}}
                    return FakeResponse({**response.json(), **changes[fault]})
            with self.subTest(fault=fault), patch.object(self.server.httpx, "AsyncClient", FaultClient):
                response = self.client.post("/api/practice/P02/verify", headers=self.headers)
                self.assertEqual(response.status_code, 502)
                self.assertIs(response.json()["detail"]["task_completed"], False)
                self.assertEqual(response.json()["detail"]["security_verdict"], "ERR")
                self.assertFalse(self.server.ACTIVE_SESSIONS)

    def test_p03_verifier_errors_and_mismatched_results_are_incomplete(self):
        for fault in ("http", "network", "shape", "suite", "activity", "contract", "verdict", "completion"):
            class FaultClient(FakeAsyncClient):
                async def post(inner, url, **kwargs):
                    response = await super().post(url, **kwargs)
                    if not url.endswith("/v1/verify/p03"):
                        return response
                    if fault == "http":
                        return FakeResponse({}, status_code=503)
                    if fault == "network":
                        raise httpx.ConnectError("unavailable")
                    if fault == "shape":
                        return FakeResponse([])
                    changes = {"suite": {"execution_id": "another-run"},
                               "activity": {"activity_id": "P01"},
                               "contract": {"contract_version": "old"},
                               "verdict": {"security_verdict": "ERR"},
                               "completion": {"task_completed": "true"}}
                    return FakeResponse({**response.json(), **changes[fault]})
            with self.subTest(fault=fault), patch.object(self.server.httpx, "AsyncClient", FaultClient):
                response = self.client.post("/api/practice/P03/verify", headers=self.headers)
                self.assertEqual(response.status_code, 502)
                self.assertIs(response.json()["detail"]["task_completed"], False)
                self.assertEqual(response.json()["detail"]["security_verdict"], "ERR")
                self.assertFalse(self.server.ACTIVE_SESSIONS)

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
        self.assertEqual(response.json()["activity_id"], "P03")
        self.assertEqual(len(FakeAsyncClient.calls), 2)
        run, verifier = FakeAsyncClient.calls
        self.assertTrue(run["url"].endswith("/v1/run"))
        self.assertTrue(verifier["url"].endswith("/v1/verify/p03"))
        self.assertEqual(set(run["json"]), {"suite_id"})
        self.assertEqual(run["json"], verifier["json"])

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
        self.assertFalse(response.json()["task_completed"])
        self.assertTrue(response.json()["resource_ready"])
        self.assertNotIn("security_verdict", response.json())
        self.assertEqual(len(FakeAsyncClient.calls), 1)
        self.assertTrue(FakeAsyncClient.calls[0]["url"].endswith("/v1/p03/resources/prepare"))
        self.assertEqual(set(FakeAsyncClient.calls[0]["json"]), {"operation_id"})

    def test_p03_preparation_mismatch_is_error_and_releases_session(self):
        for field, value in (("practice_id", "P02"), ("operation_id", "other"), ("state", "preparing"),
                             ("resources", {"provider_mode": "contract"}), ("evidence", None)):
            with self.subTest(field=field):
                class BrokenPreparationClient(FakeAsyncClient):
                    async def post(inner, url, **kwargs):
                        response = await super().post(url, **kwargs)
                        response.payload[field] = value
                        return response
                with patch.object(self.server.httpx, "AsyncClient", BrokenPreparationClient):
                    result = self.client.post("/api/practice/P03/provision", headers=self.headers)
                self.assertEqual(result.status_code, 502)
                self.assertFalse(result.json()["detail"]["task_completed"])
                self.assertEqual(result.json()["detail"]["activity_id"], "P03")
                self.assertFalse(self.server.ACTIVE_SESSIONS)

    def test_p03_preparation_timeout_does_not_claim_no_cloud_changes(self):
        class TimedOutClient(FakeAsyncClient):
            async def post(inner, url, **kwargs):
                raise httpx.ReadTimeout("provider response unavailable")
        with patch.object(self.server.httpx, "AsyncClient", TimedOutClient):
            result = self.client.post("/api/practice/P03/provision", headers=self.headers)
        self.assertEqual(result.status_code, 502)
        self.assertIn("남아 있을 수", result.json()["detail"]["next_check"])
        self.assertFalse(self.server.ACTIVE_SESSIONS)

    def test_retired_h04_actions_never_start_work(self):
        with patch.object(self.server.httpx, "AsyncClient") as downstream:
            for action in ("verify", "provision"):
                path = "/api/hands-on/H04/" + action
                for body in ({}, {"guardrail_id": "caller", "task_completed": True}):
                    response = self.client.post(path, json=body, headers=self.headers)
                    self.assertEqual(response.status_code, 410)
                    self.assertIn("/api/practice/P04", response.json()["detail"])
                    self.assertNotIn("task_completed", response.json())
                self.assertEqual(self.client.post(path).status_code, 403)
                self.assertEqual(TestClient(self.server.app).post(path).status_code, 401)
            downstream.assert_not_called()
        self.assertFalse(self.server.ACTIVE_SESSIONS)

    def test_practice_envelope_reuses_all_internal_ids_and_verdicts(self):
        for number in range(1, 23):
            for verdict in ("PASS", "HIT", "ERR"):
                original = {"activity_id": f"H{number:02d}", "course_verdict": verdict,
                            "result": {"receipt": "existing-evidence"}}
                result = self.server.practice_envelope(original, f"P{number:02d}")
                self.assertEqual(result["activity_id"], f"P{number:02d}")
                self.assertEqual(result["internal_activity_id"], original["activity_id"])
                self.assertEqual(result["security_verdict"], verdict)
                self.assertEqual(result["task_completed"], verdict == "PASS")
                self.assertEqual(result["result"], original["result"])

    def test_practice_envelope_preserves_existing_completion_decision(self):
        payload = {"activity_id": "H05", "course_verdict": "PASS", "task_completed": False}
        self.assertFalse(self.server.practice_envelope(payload, "P05")["task_completed"])
        native = {"activity_id": "P01", "task_completed": False, "security_verdict": "ERR"}
        self.assertIs(self.server.practice_envelope(native, "P01"), native)

    def test_p05_public_route_reuses_h05_verifier_and_execution(self):
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post("/api/practice/P05/verify", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["activity_id"], "P05")
        self.assertEqual(response.json()["internal_activity_id"], "H05")
        self.assertEqual(response.json()["security_verdict"], response.json()["course_verdict"])
        self.assertIsInstance(response.json()["task_completed"], bool)
        self.assertTrue(any("lab-05" in call["url"] for call in FakeAsyncClient.calls))

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

    def test_h09_uses_server_owned_cases_and_closes_sink_before_verification(self):
        rejected = self.client.post(
            "/api/hands-on/H09/verify",
            json={"case_id": "attacker-case", "course_verdict": "PASS"},
            headers=self.headers,
        )
        self.assertEqual(rejected.status_code, 422)

        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/hands-on/H09/verify", headers=self.headers
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["activity_id"], "H09")
        calls = FakeAsyncClient.calls
        prepare_index = next(
            index
            for index, item in enumerate(calls)
            if "guided-h09-delivery-sink" in item["url"]
            and item["url"].endswith("/v1/suites")
        )
        learner_index = next(
            index
            for index, item in enumerate(calls)
            if "guided-h09-presidio-redaction" in item["url"]
            and item["url"].endswith("/v1/run")
        )
        close_index = next(
            index
            for index, item in enumerate(calls)
            if "guided-h09-delivery-sink" in item["url"]
            and item["url"].endswith("/close")
        )
        verify_index = next(
            index for index, item in enumerate(calls) if item["url"].endswith("/v1/verify/h09")
        )
        self.assertLess(prepare_index, learner_index)
        self.assertLess(learner_index, close_index)
        self.assertLess(close_index, verify_index)
        learner = calls[learner_index]["json"]
        self.assertEqual(
            [item["case_id"] for item in learner["cases"]],
            ["clean", "input-email", "input-kr-rrn", "output-email"],
        )
        self.assertTrue(
            all(set(item) == {"case_id", "execution_id", "capability"} for item in learner["cases"])
        )
        self.assertNotIn("course_verdict", calls[verify_index]["json"])
        self.assertNotIn("unit-h09-sink-control", response.text)

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

    def test_p17_uses_dedicated_runtime_and_has_no_toggle_answer(self):
        class P17Client(FakeAsyncClient):
            async def post(self, url, *, json=None, headers):
                self.calls.append({'url': url, 'json': json, 'headers': headers})
                return FakeResponse({'activity_id': 'P17', 'task_completed': False, 'security_verdict': 'ERR'})
        with patch.object(self.server.httpx, 'AsyncClient', P17Client):
            rejected = self.client.post('/api/hands-on/H17/verify', headers=self.headers,
                                        json={'task_completed': True})
            self.assertEqual(rejected.status_code, 422)
            self.assertEqual(FakeAsyncClient.calls, [])
            response = self.client.post('/api/hands-on/H17/verify', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        run, verify = FakeAsyncClient.calls
        self.assertEqual(run['url'], self.server.H17_URL + '/v1/run/H17')
        self.assertEqual(run['headers'], {'Authorization': 'Bearer unit-control-h17'})
        self.assertEqual(verify['url'], self.server.VERIFIER_URL + '/v1/verify/h17')
        self.assertEqual(run['json'], verify['json'])
        page = self.client.get('/').text
        self.assertNotIn('EXPORT_TO_ALLOY', page)
        self.assertIn('P17 현재 구현 검증', page)
        self.assertIn('guided-h17-telemetry', page)
        self.assertIn('aria-controls="h17-help"', page)

    def test_p19_uses_dedicated_runtime_and_server_owned_verification(self):
        result = {"activity_id": "P19", "task_completed": False,
                  "security_verdict": "ERR", "result": {"failed_requirement": "unfinished"}}

        class P19Client(FakeAsyncClient):
            async def post(self, url, *, json=None, headers):
                self.calls.append({"url": url, "json": json, "headers": headers})
                return FakeResponse(result if url.endswith("/v1/verify/h19") else {"closed": True})

        with patch.object(self.server.httpx, "AsyncClient", P19Client):
            rejected = self.client.post("/api/hands-on/H19/verify", headers=self.headers,
                                        json={"task_completed": True, "suite_id": "browser-selected"})
            self.assertEqual(rejected.status_code, 422)
            self.assertEqual(FakeAsyncClient.calls, [])
            response = self.client.post("/api/hands-on/H19/verify", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), result)
        run, verify = FakeAsyncClient.calls
        self.assertEqual(run["url"], self.server.H19_URL + "/v1/run/H19")
        self.assertEqual(run["headers"], {"Authorization": "Bearer unit-control-h19"})
        self.assertNotEqual(self.server.H19_URL, self.server.OBSERVABILITY_URL)
        self.assertEqual(verify["url"], self.server.VERIFIER_URL + "/v1/verify/h19")
        self.assertEqual(verify["headers"], {"Authorization": "Bearer unit-control-verifier"})
        self.assertEqual(run["json"], verify["json"])
        self.assertEqual(set(run["json"]), {"suite_id", "started_at"})

    def test_unknown_host_is_rejected(self):
        response = self.client.get("/", headers={"Host": "attacker.example"})
        self.assertEqual(response.status_code, 421)

    def test_p20_dedicated_runtime_and_problem_without_solution(self):
        result = {'activity_id': 'P20', 'task_completed': False, 'security_verdict': 'ERR'}
        class P20Client(FakeAsyncClient):
            async def post(self, url, *, json=None, headers):
                self.calls.append({'url': url, 'json': json, 'headers': headers})
                return FakeResponse(result if url.endswith('/v1/verify/h20') else {'closed': False})
        with patch.object(self.server, 'H20_TOKEN', 'p20-control'), patch.object(self.server.httpx, 'AsyncClient', P20Client):
            self.assertEqual(self.client.post('/api/hands-on/H20/verify', headers=self.headers,
                json={'task_completed': True}).status_code, 422)
            self.assertEqual(FakeAsyncClient.calls, [])
            response = self.client.post('/api/hands-on/H20/verify', headers=self.headers)
        self.assertEqual(response.json(), result)
        run, verify = FakeAsyncClient.calls
        self.assertEqual(run['url'], self.server.H20_URL + '/v1/run/H20')
        self.assertEqual(run['headers'], {'Authorization': 'Bearer p20-control'})
        self.assertEqual(run['json'], verify['json'])
        self.assertEqual(verify['url'], self.server.VERIFIER_URL + '/v1/verify/h20')
        page = self.client.get('/').text
        self.assertIn('P20 현재 구현 검증', page)
        self.assertIn('aria-controls="h20-help"', page)
        self.assertNotIn('guided_h20_risk_active', page)
        self.assertNotIn('dashboard-query.txt', page)
        self.assertIn('h20-alert-dashboard/rules.yaml', page)

    def test_p20_missing_connection_does_not_call_shared_observability(self):
        with patch.object(self.server, 'H20_TOKEN', ''), patch.object(self.server.httpx, 'AsyncClient', FakeAsyncClient):
            response = self.client.post('/api/hands-on/H20/verify', headers=self.headers)
        self.assertEqual(response.status_code, 502)
        self.assertFalse(response.json()['detail']['task_completed'])
        self.assertEqual(FakeAsyncClient.calls, [])
        self.assertEqual(self.client.get('/readyz').status_code, 200)

    def test_p19_transport_errors_are_incomplete_without_claiming_no_calls(self):
        for failure_at in ('learner_execution', 'evidence_verification'):
            for failure_type in ('connection', 'status', 'json'):
                if failure_at == 'learner_execution' and failure_type == 'json':
                    continue
                FakeAsyncClient.calls.clear()

                class BrokenClient(FakeAsyncClient):
                    async def post(self, url, *, json=None, headers):
                        self.calls.append(url)
                        stage = 'evidence_verification' if '/v1/verify/' in url else 'learner_execution'
                        if stage == failure_at:
                            if failure_type == 'connection':
                                raise httpx.ConnectError('unavailable')
                            if failure_type == 'status':
                                return FakeResponse({}, 503)
                            return httpx.Response(200, text='not-json')
                        return FakeResponse({})

                with self.subTest(stage=failure_at, failure=failure_type), patch.object(
                        self.server.httpx, 'AsyncClient', BrokenClient):
                    response = self.client.post('/api/hands-on/H19/verify', headers=self.headers)
                    self.assertEqual(response.status_code, 502)
                    detail = response.json()['detail']
                    self.assertEqual(detail['activity_id'], 'P19')
                    self.assertFalse(detail['task_completed'])
                    self.assertEqual(detail['security_verdict'], 'ERR')
                    self.assertEqual(detail['stopped_stage'], failure_at)
                    self.assertNotIn('downstream_called', detail)
                    self.assertEqual(len(FakeAsyncClient.calls), 1 if failure_at == 'learner_execution' else 2)
                    self.assertEqual(self.client.get('/readyz').status_code, 200)

    def test_session_store_evicts_idle_sessions_at_the_limit(self):
        with patch.object(self.server, "MAX_SESSIONS", 2):
            self.client.get("/")
            self.client.get("/")
        self.assertEqual(len(self.server.SESSIONS), 2)
        self.assertFalse(self.server.ACTIVE_SESSIONS)

    def test_rendering_uses_text_nodes_only(self):
        html = (CONTROL / "guided-control-center/index.html").read_text(encoding="utf-8")
        self.assertNotIn("effective_max_tokens = min(request.max_output_tokens, 128)", html)
        self.assertNotIn('result = boto3.client("bedrock-runtime"', html)
        self.assertIn("h01-bedrock-gateway/learner.py", html)
        self.assertIn("handle_request(body, client)", html)
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
            "h09-verify": "h09-verify-help",
            "h21-verify": "h21-verify-help",
            "h22-verify": "h22-verify-help",
        }
        for button_id, tooltip_id in action_help.items():
            self.assertIn(f'id="{button_id}"', html)
            self.assertIn(f'aria-describedby="{tooltip_id}"', html)
            self.assertIn(f'id="{tooltip_id}" class="action-tooltip" role="tooltip"', html)
        self.assertIn("AWS 자격 증명과 모델 연결", html)
        self.assertIn("S3 Vector Index", html)
        self.assertIn("복구 코드 요청을 거부하는 Bot 응답", html)
        self.assertNotIn('"복구 코드는 공개할 수 없습니다."', html)
        self.assertIn("NeMo Topical 평가", html)
        self.assertIn("판정 응답은 차단 시", html)
        self.assertIn("다른 공격 문장까지 모두 막는다는 뜻은 아닙니다", html)
        self.assertIn("실제로 받은 digest", html)
        self.assertIn("Token 제한 코드가 맞다는 뜻은 아닙니다", html)
        javascript = (CONTROL / "guided-control-center/app.js").read_text(encoding="utf-8")
        self.assertIn("textContent", javascript)
        self.assertNotIn("innerHTML", javascript)
        self.assertIn('matchMedia("(prefers-color-scheme: dark)")', javascript)
        self.assertIn('localStorage.setItem("guided-theme-mode", mode)', javascript)
        self.assertIn('/api/practice/P01/chat', javascript)
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

    def test_only_named_public_assets_are_served_not_source_or_course_files(self):
        paths = ("/server.py", "/p01.json", "/Containerfile", "/requirements.txt",
                 "/solutions/p01.py", "/index.html", "/.state/guided-course.env",
                 "/guided-labs/h01-bedrock-gateway/learner.py", "/api/solutions")
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)

    def test_web_code_blocks_only_contain_apply_commands_and_resource_templates(self):
        html = self.home.text
        blocks = re.findall(r"<pre>([\s\S]*?)</pre>", html)
        self.assertGreater(len(blocks), 20)
        templates = []
        for block in blocks:
            text = html_module.unescape(block).strip()
            if text.startswith("{"):
                templates.append(json.loads(text))
                continue
            self.assertTrue(text.startswith("docker compose "), text[:120])
            self.assertNotIn("cat >", text)
            self.assertNotIn("python -c", text)
        self.assertEqual(len(templates), 2)
        self.assertEqual(templates[0]["embeddingModelId"], "amazon.titan-embed-text-v2:0")
        self.assertEqual(templates[1]["piiType"], "EMAIL")

    def test_served_assets_do_not_contain_removed_solution_fragments(self):
        assets = "\n".join(self.client.get(path).text for path in ("/", "/app.js", "/app.css", "/api/bootstrap"))
        forbidden = (
            "def prepare_document", "return same_job and status",
            "USE_GUARDRAIL_FOR_CONVERSE = True", "define bot refuse recovery code",
            'ALLOWED_ACTIONS = frozenset({"get_account_balance"})',
            "- content safety check input $model=content_safety",
            "Return exactly Yes when the request must be blocked.",
            "analyzer.registry.add_recognizer(", "Block synthetic recovery codes",
            'roles = set(principal["roles"])', "def stage_order()",
            "const r = JSON.parse(output);", "soft_probe_prompt_cap: 4",
            "MAX_TURNS = 3", 'return "block" if "H16-OVERRIDE"',
            'if model not in configured["models"]:', "nonce = verify_approval(",
        )
        for fragment in forbidden:
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, html_module.unescape(assets))

    def test_p18_problem_contains_contract_but_not_completed_queries(self):
        html = (CONTROL / "guided-control-center/index.html").read_text(encoding="utf-8")
        problem = html.split('<div id="h18-work"', 1)[1].split('<div id="h19-work"', 1)[0]
        for required in ('P18 현재 구현 검증', 'guided-h18-queries', 'queries.yaml',
                         'request_id', 'Counter', '--no-deps', 'aria-controls="h18-help"'):
            self.assertIn(required, problem)
        for solution in ('logql:', 'promql:', 'sum(', 'max by ('):
            self.assertNotIn(solution, problem)
        self.assertNotIn('build guided-observability', problem)

    def test_p19_problem_has_function_contract_not_answer_constant(self):
        html = (CONTROL / "guided-control-center/index.html").read_text(encoding="utf-8")
        problem = html.split('<div id="h19-work"', 1)[1].split('<div id="h20-work"', 1)[0]
        self.assertNotIn('JOIN_KEY', problem)
        for required in ('P19 현재 구현 검증', 'analyze_incident', 'downstream_calls', 'ValueError',
                         'build guided-h19-investigation', '--no-deps', '교육용 공지 저장소',
                         'aria-controls="h19-help"', 'aria-expanded="false"'):
            self.assertIn(required, problem)

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

    def test_only_front_proxy_and_official_uis_own_loopback_ports(self):
        compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
        owners = [name for name, service in compose["services"].items() if "ports" in service]
        self.assertEqual(
            set(owners),
            {
                "guided-front-proxy",
                "guided-grafana",
                "guided-h20-grafana",
                "guided-promptfoo-ui",
                "guided-pyrit-ui",
            },
        )
        self.assertEqual(len(compose["services"]["guided-front-proxy"]["ports"]), 2)
        for owner in owners:
            self.assertTrue(
                all(str(port).startswith("127.0.0.1:") for port in compose["services"][owner]["ports"]),
                owner,
            )
        verifier = compose["services"]["guided-evidence-verifier"]
        serialized = str(verifier)
        self.assertNotIn("/tmp/.aws", serialized)
        self.assertNotIn("docker.sock", serialized)
        self.assertIn("guided-h01-gateway", compose["services"])
        self.assertIn("guided-h02-document-app", compose["services"])
        self.assertIn("guided-h03-sync-app", compose["services"])
        self.assertIn("guided-h08-self-check-input", compose["services"])
        self.assertIn("guided-h09-presidio-redaction", compose["services"])
        self.assertIn("guided-h09-delivery-sink", compose["services"])
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
        h09 = compose["services"]["guided-h09-presidio-redaction"]
        sink = compose["services"]["guided-h09-delivery-sink"]
        self.assertIn("guided-h09-receipts:/state:rw", h09["volumes"])
        self.assertIn("guided-h09-sink-ledger:/state:rw", sink["volumes"])
        self.assertNotIn("/tmp/.aws", str(h09))
        self.assertNotIn("/tmp/.aws", str(sink))
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
            "GUIDED_CONTROL_LAB09_TOKEN",
            "GUIDED_VERIFIER_LAB09_TOKEN",
            "GUIDED_H09_SINK_CONTROL_TOKEN",
            "GUIDED_H09_SINK_VERIFIER_TOKEN",
            "GUIDED_H09_CAPABILITY_SECRET",
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
        self.assertIn('boto3.client("bedrock-runtime", region_name=REGION)', source)
        self.assertIn("learner.handle_request(body, recorder)", source)
        learner_source = (CONTROL / "guided-labs/h01-bedrock-gateway/learner.py").read_text()
        self.assertIn("raise NotImplementedError", learner_source)
        self.assertNotIn("min(", learner_source)

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
        self.assertEqual(len(manifest["tabs"]), 13)
        self.assertEqual(len(hands_on), 22)
        self.assertEqual(len(set(hands_on)), 22)
        self.assertEqual(manifest["workspace"], "practice")
        self.assertEqual(manifest["execution_ids"],
                         {f"P{i:02d}": f"H{i:02d}" for i in range(1, 23)})
        self.assertEqual(hands_on[0], "H01")
        self.assertTrue(all("practice" not in tab for tab in manifest["tabs"]))
        self.assertTrue(all("practice_status" not in tab for tab in manifest["tabs"]))
        self.assertEqual(manifest["tabs"][0]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][1]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][1]["implemented_hands_on"], ["H02", "H03"])
        self.assertEqual(manifest["tabs"][2]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][2]["implemented_hands_on"], ["H04"])
        self.assertEqual(manifest["tabs"][3]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][3]["implemented_hands_on"], ["H05", "H06"])
        self.assertEqual(manifest["tabs"][4]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][4]["implemented_hands_on"], ["H07", "H08"])
        self.assertEqual(manifest["tabs"][5]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][5]["implemented_hands_on"], ["H09", "H10"])
        self.assertEqual(
            manifest["hands_on_H08"]["source_path"],
            "guided-labs/h08-self-check-input/config/prompts.yml",
        )
        self.assertEqual(
            manifest["hands_on_H08"]["control_endpoint"],
            "/api/hands-on/H08/verify",
        )
        self.assertEqual(
            manifest["hands_on_H09"]["source_path"],
            "guided-labs/h09-presidio-redaction/policy.py",
        )
        self.assertEqual(
            manifest["hands_on_H09"]["control_endpoint"],
            "/api/hands-on/H09/verify",
        )
        self.assertTrue(all(tab["hands_on_status"] == "implemented" for tab in manifest["tabs"][6:12]))
        self.assertEqual(manifest["tabs"][12]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][12]["implemented_hands_on"], ["H21", "H22"])


if __name__ == "__main__":
    unittest.main()
