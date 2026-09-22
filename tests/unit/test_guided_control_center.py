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

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def post(self, url, *, json, headers):
        self.calls.append({"url": url, "json": json, "headers": headers})
        return FakeResponse()


class GuidedControlCenterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server()
        cls.client = TestClient(cls.server.app)

    def setUp(self):
        FakeAsyncClient.calls.clear()

    def test_page_contains_exactly_22_lessons_and_mobile_layout(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text.count("{chapter:"), 22)
        self.assertIn("@media (max-width:760px)", response.text)
        self.assertIn("실제 요청", response.text)
        self.assertIn("검증된 저장 기록", response.text)
        self.assertNotIn("__APP_VERSION__", response.text)

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
        guided = compose.split("  guided-control-center:", 1)[1].split("\n  dialog:", 1)[0]
        self.assertIn("profiles: [guided]", guided)
        self.assertIn('127.0.0.1:${GUIDED_HOST_PORT:-18097}:8000', guided)
        self.assertIn("APPLICATION_URL: http://llm-security-application-gateway:8000", guided)
        self.assertNotIn("BEDROCK_GATEWAY_TOKEN", guided)
        self.assertNotIn("APPLICATION_INTERNAL_TOKEN", guided)


if __name__ == "__main__":
    unittest.main()
