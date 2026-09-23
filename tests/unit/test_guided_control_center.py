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
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "llm-security-control-plane"
COMPOSE = ROOT / "examples/security-monitoring/compose.guided.yaml"
os.environ.setdefault("GUIDED_SESSION_SECRET", "unit-session-secret")
os.environ.setdefault("GUIDED_CONTROL_LAB01_TOKEN", "unit-control-lab")
os.environ.setdefault("GUIDED_CONTROL_LAB02_TOKEN", "unit-control-lab02")
os.environ.setdefault("GUIDED_CONTROL_LAB03_TOKEN", "unit-control-lab03")
os.environ.setdefault("GUIDED_CONTROL_H21_TOKEN", "unit-control-h21")
os.environ.setdefault("GUIDED_CONTROL_H22_TOKEN", "unit-control-h22")
os.environ.setdefault("GUIDED_CONTROL_VERIFIER_TOKEN", "unit-control-verifier")
os.environ.setdefault("GUIDED_LAB02_PROVISION_TOKEN", "unit-provision-lab02")
os.environ.setdefault("GUIDED_LAB03_PROVISION_TOKEN", "unit-provision-lab03")


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

    async def get(self, url, *, headers):
        self.calls.append({"url": url, "json": None, "headers": headers})
        if "/v1/status/" in url:
            return FakeResponse({"ingestion_job_id": "H03JOB", "status": "COMPLETE"})
        return FakeResponse({"detail": "not found"}, status_code=404)

    async def post(self, url, *, json=None, headers):
        self.calls.append({"url": url, "json": json, "headers": headers})
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
        if url.endswith("/v1/sync"):
            return FakeResponse({"ingestion_job_id": "H03JOB", "status": "STARTING"})
        if url.endswith("/v1/search"):
            return FakeResponse({"retrieval_called": True, "source_uris": ["s3://current"]})
        if url.endswith("/v1/documents"):
            if not json["body"]:
                return FakeResponse({"detail": "invalid request"}, status_code=422)
            return FakeResponse({"execution_id": json["execution_id"]})
        activity_id = "H22" if "lab-22" in url else "H21" if "lab-21" in url else "H03" if "lab-03" in url else "H02" if "lab-02" in url else "H01"
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
        self.assertEqual(self.bootstrap["course"]["implemented_hands_on"], ["H01", "H02", "H03", "H21", "H22"])
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
            "h21-verify": "h21-verify-help",
            "h22-verify": "h22-verify-help",
        }
        for button_id, tooltip_id in action_help.items():
            self.assertIn(f'id="{button_id}"', html)
            self.assertIn(f'aria-describedby="{tooltip_id}"', html)
            self.assertIn(f'id="{tooltip_id}" class="action-tooltip" role="tooltip"', html)
        self.assertIn("AWS 자격 증명과 모델 연결", html)
        self.assertIn("S3 Vector Index", html)
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
        self.assertIn("guided-h21-host", compose["services"])
        self.assertIn("guided-h21-provider", compose["services"])
        self.assertIn("guided-h21-trusted-mcp", compose["services"])
        self.assertIn("guided-h21-untrusted-mcp", compose["services"])
        self.assertIn("guided-h22-mcp-server", compose["services"])
        self.assertIn("guided-h22-host", compose["services"])
        self.assertIn("guided-bedrock-gateway", compose["services"])
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
        self.assertTrue(all(tab["hands_on_status"] == "planned" for tab in manifest["tabs"][2:12]))
        self.assertEqual(manifest["tabs"][12]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][12]["implemented_hands_on"], ["H21", "H22"])
        self.assertTrue(
            all(tab["practice_status"] == "planned" for tab in manifest["tabs"])
        )


if __name__ == "__main__":
    unittest.main()
