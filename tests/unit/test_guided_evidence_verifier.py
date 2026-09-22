"""Read-only verifier freshness and trust-boundary tests."""

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
CONTROL = ROOT / "llm-security-control-plane"


class FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload


class GuidedEvidenceVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        os.environ["GUIDED_CONTROL_VERIFIER_TOKEN"] = "control-verifier"
        os.environ["GUIDED_VERIFIER_LAB01_TOKEN"] = "verifier-lab"
        os.environ["GUIDED_VERIFIER_GATEWAY_TOKEN"] = "verifier-gateway"
        os.environ["GUIDED_VERIFIER_DATABASE"] = str(Path(cls.temp.name) / "verifier.sqlite3")
        spec = importlib.util.spec_from_file_location(
            "guided_evidence_verifier_server",
            CONTROL / "guided-evidence-verifier/server.py",
        )
        cls.server = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = cls.server
        spec.loader.exec_module(cls.server)
        cls.client = TestClient(cls.server.app)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def request_body(self, execution_id: str) -> dict:
        return {
            "execution_id": execution_id,
            "started_at": "2026-09-22T10:00:00+00:00",
            "expected_config_digest": "a" * 64,
            "expected_max_output_tokens": 80,
            "run_kind": "bounded",
        }

    def fake_get(self, provider_id: str, execution_id: str, observed_at: str):
        def get(url, **_kwargs):
            if "/receipts/" in url:
                return FakeResponse(
                    {
                        "execution_id": execution_id,
                        "provider_request_id": provider_id,
                        "config_digest": "a" * 64,
                    }
                )
            return FakeResponse(
                {
                    "execution_id": execution_id,
                    "provider_request_id": provider_id,
                    "provider_mode": "aws",
                    "observed_at": observed_at,
                    "model_id": "us.amazon.nova-lite-v1:0",
                    "region": "us-east-1",
                    "forwarded_parameters": {"maxTokens": 80, "temperature": 0.0},
                    "usage": {"inputTokens": 10, "outputTokens": 40, "totalTokens": 50},
                    "stop_reason": "end_turn",
                    "output_text": "검증된 응답",
                    "config_digest": "a" * 64,
                }
            )

        return get

    def verify(self, body: dict):
        return self.client.post(
            "/v1/verify/lab-01",
            json=body,
            headers={"Authorization": "Bearer control-verifier"},
        )

    def test_valid_provider_receipt_is_pass(self):
        execution_id = "11111111-1111-1111-1111-111111111111"
        with patch.object(
            self.server.httpx,
            "get",
            self.fake_get("aws-request-valid", execution_id, "2026-09-22T10:00:01+00:00"),
        ):
            response = self.verify(self.request_body(execution_id))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "PASS")
        self.assertEqual(response.json()["verified_by"], "guided-evidence-verifier")
        self.assertEqual(response.json()["evidence"][0]["id"], "aws-request-valid")

    def test_provider_receipt_reuse_for_another_execution_is_err(self):
        first_execution = "22222222-2222-2222-2222-222222222221"
        with patch.object(
            self.server.httpx,
            "get",
            self.fake_get("aws-request-reused", first_execution, "2026-09-22T10:00:01+00:00"),
        ):
            first = self.verify(self.request_body(first_execution))
        self.assertEqual(first.json()["course_verdict"], "PASS")

        execution_id = "22222222-2222-2222-2222-222222222222"
        with patch.object(
            self.server.httpx,
            "get",
            self.fake_get("aws-request-reused", execution_id, "2026-09-22T10:00:02+00:00"),
        ):
            response = self.verify(self.request_body(execution_id))
        self.assertEqual(response.json()["course_verdict"], "ERR")
        self.assertIn("stale", response.json()["reason"])

    def test_evidence_before_execution_is_err(self):
        execution_id = "33333333-3333-3333-3333-333333333333"
        with patch.object(
            self.server.httpx,
            "get",
            self.fake_get("aws-request-old", execution_id, "2026-09-22T09:59:59+00:00"),
        ):
            response = self.verify(self.request_body(execution_id))
        self.assertEqual(response.json()["course_verdict"], "ERR")

    def test_browser_or_executor_verdict_field_is_rejected(self):
        body = self.request_body("44444444-4444-4444-4444-444444444444")
        response = self.verify({**body, "course_verdict": "PASS"})
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
