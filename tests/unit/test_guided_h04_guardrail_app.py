"""H04 learner app source and service-boundary tests."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "llm-security-control-plane/guided-labs/h04-bedrock-guardrail/server.py"


class FakeResponse:
    status_code = 200

    def __init__(self, payload: dict):
        self.payload = payload

    def json(self):
        return self.payload


class GuidedH04GuardrailAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        os.environ.update(
            {
                "GUIDED_H04_GATEWAY_TOKEN": "h04-gateway",
                "GUIDED_CONTROL_LAB04_TOKEN": "h04-control",
                "GUIDED_VERIFIER_LAB04_TOKEN": "h04-verifier",
                "GUIDED_H04_DATABASE": str(Path(cls.temp.name) / "h04.sqlite3"),
            }
        )
        spec = importlib.util.spec_from_file_location("guided_h04_app", APP)
        cls.server = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = cls.server
        spec.loader.exec_module(cls.server)
        cls.client = TestClient(cls.server.app)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_starter_runs_standalone_but_does_not_attach_to_converse(self):
        execution_id = "04000000-0000-0000-0000-000000000001"
        provider = {
            "provider_request_id": "contract-h04-risk",
            "output_text": "담당자 이메일은 learner@example.com 입니다.",
        }
        with patch.object(
            self.server.httpx, "post", return_value=FakeResponse(provider)
        ) as post:
            response = self.client.post(
                "/v1/run",
                json={
                    "execution_id": execution_id,
                    "started_at": "2026-09-23T10:00:00+00:00",
                    "case_id": "converse-risk",
                },
                headers={"Authorization": "Bearer h04-control"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(post.call_args.kwargs["json"]["attach_guardrail"])
        self.assertNotIn("guardrail_id", post.call_args.kwargs["json"])

    def test_browser_cannot_choose_guardrail_or_verdict(self):
        response = self.client.post(
            "/v1/run",
            json={
                "execution_id": "04000000-0000-0000-0000-000000000002",
                "started_at": "2026-09-23T10:00:00+00:00",
                "case_id": "converse-risk",
                "guardrail_id": "attacker",
                "course_verdict": "PASS",
            },
            headers={"Authorization": "Bearer h04-control"},
        )
        self.assertEqual(response.status_code, 422)

    def test_receipt_requires_verifier_identity(self):
        response = self.client.get(
            "/v1/receipts/04000000-0000-0000-0000-000000000001",
            headers={"Authorization": "Bearer wrong"},
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
