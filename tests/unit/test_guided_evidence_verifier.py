"""Read-only suite verification and trust-boundary tests."""

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

    def setUp(self):
        with self.server.connect() as database:
            database.execute("DELETE FROM used_evidence")

    def body(self) -> dict:
        return {
            "suite_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "started_at": "2026-09-22T10:00:00+00:00",
            "suite_kind": "hands_on",
            "cases": [
                {
                    "case_id": "normal-64",
                    "scenario": "normal",
                    "execution_id": "11111111-1111-1111-1111-111111111111",
                    "started_at": "2026-09-22T10:00:00+00:00",
                    "requested_max_output_tokens": 64,
                },
                {
                    "case_id": "risk-512",
                    "scenario": "risk",
                    "execution_id": "22222222-2222-2222-2222-222222222222",
                    "started_at": "2026-09-22T10:00:00+00:00",
                    "requested_max_output_tokens": 512,
                },
            ],
        }

    def fake_get(self, risk_effective: int):
        cases = {
            "11111111-1111-1111-1111-111111111111": ("normal", 64, 64, 40),
            "22222222-2222-2222-2222-222222222222": (
                "risk",
                512,
                risk_effective,
                risk_effective,
            ),
        }

        def get(url, **_kwargs):
            execution_id = url.rsplit("/", 1)[-1]
            scenario, requested, effective, output = cases[execution_id]
            provider_id = f"request-{execution_id[:8]}-{effective}"
            digest = self.server.config_digest(effective)
            if "/receipts/" in url:
                return FakeResponse(
                    {
                        "execution_id": execution_id,
                        "scenario": scenario,
                        "requested_max_output_tokens": requested,
                        "effective_max_output_tokens": effective,
                        "policy_digest": "b" * 64,
                        "provider_request_id": provider_id,
                        "config_digest": digest,
                    }
                )
            return FakeResponse(
                {
                    "execution_id": execution_id,
                    "provider_request_id": provider_id,
                    "provider_mode": "contract",
                    "observed_at": "2026-09-22T10:00:01+00:00",
                    "model_id": "us.amazon.nova-lite-v1:0",
                    "region": "us-east-1",
                    "forwarded_parameters": {"maxTokens": effective, "temperature": 0.0},
                    "usage": {"inputTokens": 10, "outputTokens": output, "totalTokens": 10 + output},
                    "stop_reason": "max_tokens",
                    "output_text": "검증된 응답",
                    "config_digest": digest,
                }
            )

        return get

    def verify(self, body: dict):
        return self.client.post(
            "/v1/verify/lab-01",
            json=body,
            headers={"Authorization": "Bearer control-verifier"},
        )

    def test_safe_learner_policy_is_pass(self):
        with patch.object(self.server.httpx, "get", self.fake_get(128)):
            response = self.verify(self.body())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "PASS")
        self.assertEqual(len(response.json()["result"]["cases"]), 2)

    def test_unbounded_starter_is_hit(self):
        body = self.body()
        body["suite_id"] = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        with patch.object(self.server.httpx, "get", self.fake_get(512)):
            response = self.verify(body)
        self.assertEqual(response.json()["course_verdict"], "HIT")
        self.assertEqual(response.json()["result"]["effective_max_output_tokens"], 512)

    def test_incomplete_server_suite_is_err(self):
        body = self.body()
        body["suite_id"] = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        body["cases"] = body["cases"][:1]
        response = self.verify(body)
        self.assertEqual(response.json()["course_verdict"], "ERR")

    def test_provider_receipt_cannot_move_to_another_execution(self):
        self.assertTrue(self.server.reserve_provider_evidence("stale-request", "execution-one"))
        self.assertFalse(self.server.reserve_provider_evidence("stale-request", "execution-two"))

    def test_browser_or_executor_verdict_field_is_rejected(self):
        response = self.verify({**self.body(), "course_verdict": "PASS"})
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
