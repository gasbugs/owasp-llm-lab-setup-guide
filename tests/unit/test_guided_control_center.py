"""03 테넌트 Guided Control Center의 분리·프록시 계약 검사."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "llm-security-control-plane"
GUIDED = CONTROL / "guided-control-center"


def load_server():
    spec = importlib.util.spec_from_file_location("guided_control_center_server", GUIDED / "server.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    status_code = 200

    @staticmethod
    def json():
        return {"application_decision": "allow", "upstream_called": True}


class FakeAsyncClient:
    calls: list[dict] = []
    gets: list[str] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def post(self, url, *, json, headers):
        self.calls.append({"url": url, "json": json, "headers": headers})
        return FakeResponse()

    async def get(self, url):
        self.gets.append(url)
        return FakeResponse()


class GuidedControlCenterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server()
        cls.client = TestClient(cls.server.app)

    def setUp(self):
        FakeAsyncClient.calls.clear()
        FakeAsyncClient.gets.clear()

    def test_page_contains_exactly_22_lessons_and_mobile_layout(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text.count("{chapter:"), 22)
        self.assertIn("@media (max-width:760px)", response.text)
        self.assertIn("grid-template-columns:minmax(0,1fr)", response.text)
        self.assertIn(".panel { min-width:0", response.text)
        self.assertIn("실제 요청", response.text)
        self.assertIn("고정 학습 기록", response.text)
        self.assertIn("제품 공식 UI", response.text)
        self.assertNotIn("__APP_VERSION__", response.text)

    def test_official_ui_catalog_reports_local_health_without_internal_urls(self):
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.get("/api/official-uis")
        self.assertEqual(response.status_code, 200)
        items = response.json()["items"]
        self.assertEqual(len(items), 6)
        self.assertEqual({item["status"] for item in items[:4]}, {"ready"})
        self.assertEqual({item["status"] for item in items[4:]}, {"external"})
        self.assertTrue(all("health_url" not in item for item in items))
        self.assertTrue(all(url.startswith("http://llm-") for url in FakeAsyncClient.gets))

    def test_chat_is_proxied_to_application_with_bearer_token(self):
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            response = self.client.post(
                "/api/chat",
                headers={"Authorization": "Bearer learner-token"},
                json={"message": "정상 요청"},
            )
        self.assertEqual(response.status_code, 200)
        call = FakeAsyncClient.calls[0]
        self.assertTrue(call["url"].endswith("/api/chat"))
        self.assertEqual(call["headers"]["authorization"], "Bearer learner-token")
        self.assertEqual(response.json()["application_decision"], "allow")

    def test_compose_keeps_guided_service_opt_in(self):
        compose = (CONTROL / "compose.yaml").read_text(encoding="utf-8")
        guided = compose.split("  guided-control-center:", 1)[1].split(
            "\n  nemo-official-ui:", 1
        )[0]
        self.assertIn("profiles: [guided]", guided)
        self.assertIn('127.0.0.1:${GUIDED_HOST_PORT:-18097}:8000', guided)
        self.assertIn("APPLICATION_URL: http://llm-security-application-gateway:8000", guided)
        self.assertNotIn("BEDROCK_GATEWAY_TOKEN", guided)
        self.assertNotIn("APPLICATION_INTERNAL_TOKEN", guided)

    def test_compose_builds_official_uis_with_loopback_ports(self):
        compose = (CONTROL / "compose.yaml").read_text(encoding="utf-8")
        expectations = {
            "nemo-official-ui": (
                "promptfoo-official-ui",
                "${NEMO_OFFICIAL_UI_HOST_PORT:-18192}:8000",
            ),
            "promptfoo-official-ui": (
                "pyrit-official-ui",
                "${PROMPTFOO_UI_HOST_PORT:-15500}:15500",
            ),
            "pyrit-official-ui": ("dialog", "${PYRIT_UI_HOST_PORT:-18098}:8000"),
        }
        for service, (next_service, port) in expectations.items():
            section = compose.split(f"  {service}:", 1)[1].split(
                f"\n  {next_service}:", 1
            )[0]
            self.assertIn("profiles: [guided]", section)
            self.assertIn(f'127.0.0.1:{port}', section)
            self.assertIn("healthcheck:", section)
        self.assertIn("promptfoo-data:/work/.promptfoo:rw", compose)

        requirements = (
            CONTROL / "official-uis/nemo/requirements.txt"
        ).read_text(encoding="utf-8")
        promptfoo = (
            CONTROL / "official-uis/promptfoo/Containerfile"
        ).read_text(encoding="utf-8")
        pyrit = (CONTROL / "official-uis/pyrit/Containerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn("nemoguardrails[chat-ui,server]==0.22.0", requirements)
        self.assertIn("PROMPTFOO_VERSION=0.121.20", promptfoo)
        self.assertIn("PYRIT_VERSION=1.0.1", pyrit)


if __name__ == "__main__":
    unittest.main()
