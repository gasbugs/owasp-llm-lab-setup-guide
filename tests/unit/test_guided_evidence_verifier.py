"""Read-only suite verification and trust-boundary tests."""

from __future__ import annotations

import importlib.util
import hashlib
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


class FakeAsyncHttpClient:
    def __init__(self, response: FakeResponse):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def get(self, *_args, **_kwargs):
        return self.response


class FakeMcpResult:
    def __init__(self, payload: dict):
        self.structured_content = payload
        self.content = []


class FakeMcpClient:
    protocol_version = "2026-07-28"

    def __init__(self, effects: dict):
        self.effects = effects

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def list_tools(self):
        names = [
            "audit_effects",
            "lookup_notice",
            "publish_notice",
            "server_build_info",
        ]
        return type("Tools", (), {"tools": [type("Tool", (), {"name": name}) for name in names]})()

    async def call_tool(self, name: str, _arguments: dict):
        if name == "server_build_info":
            return FakeMcpResult(
                {
                    "server_id": "training-notice-mcp",
                    "protocol_version": "2026-07-28",
                    "source_digest": "e" * 64,
                }
            )
        return FakeMcpResult(self.effects)


class GuidedEvidenceVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        os.environ["GUIDED_CONTROL_VERIFIER_TOKEN"] = "control-verifier"
        os.environ["GUIDED_VERIFIER_LAB01_TOKEN"] = "verifier-lab"
        os.environ["GUIDED_VERIFIER_LAB02_TOKEN"] = "verifier-lab02"
        os.environ["GUIDED_VERIFIER_H21_TOKEN"] = "verifier-h21"
        os.environ["GUIDED_VERIFIER_H22_TOKEN"] = "verifier-h22"
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
                    "expected_status": 200,
                    "observed_status": 200,
                },
                {
                    "case_id": "risk-512",
                    "scenario": "risk",
                    "execution_id": "22222222-2222-2222-2222-222222222222",
                    "started_at": "2026-09-22T10:00:00+00:00",
                    "requested_max_output_tokens": 512,
                    "expected_status": 200,
                    "observed_status": 200,
                },
                {
                    "case_id": "invalid-empty-message",
                    "scenario": "normal",
                    "execution_id": "33333333-3333-3333-3333-333333333333",
                    "started_at": "2026-09-22T10:00:00+00:00",
                    "requested_max_output_tokens": 64,
                    "expected_status": 422,
                    "observed_status": 422,
                },
                {
                    "case_id": "reject-model-override",
                    "scenario": "normal",
                    "execution_id": "44444444-4444-4444-4444-444444444444",
                    "started_at": "2026-09-22T10:00:00+00:00",
                    "requested_max_output_tokens": 64,
                    "expected_status": 422,
                    "observed_status": 422,
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
            if url.endswith("/v1/build-info"):
                return FakeResponse({"component": "guided-h01-gateway", "source_digest": "b" * 64})
            execution_id = url.rsplit("/", 1)[-1]
            if execution_id in {
                "33333333-3333-3333-3333-333333333333",
                "44444444-4444-4444-4444-444444444444",
            }:
                return FakeResponse({"detail": "receipt not found"}, status_code=404)
            scenario, requested, effective, output = cases[execution_id]
            provider_id = f"request-{execution_id[:8]}-{effective}"
            return FakeResponse(
                {
                    "execution_id": execution_id,
                    "started_at": "2026-09-22T10:00:00+00:00",
                    "scenario": scenario,
                    "requested_max_output_tokens": requested,
                    "effective_max_output_tokens": effective,
                    "source_digest": "b" * 64,
                    "provider_request_id": provider_id,
                    "provider_mode": "contract",
                    "observed_at": "2026-09-22T10:00:01+00:00",
                    "model_id": "us.amazon.nova-lite-v1:0",
                    "region": "us-east-1",
                    "forwarded_parameters": {"maxTokens": effective, "temperature": 0.0},
                    "usage": {"inputTokens": 10, "outputTokens": output, "totalTokens": 10 + output},
                    "stop_reason": "max_tokens",
                    "response_text": "검증된 응답",
                    "upstream_called": True,
                }
            )

        return get

    def verify(self, body: dict):
        return self.client.post(
            "/v1/verify/lab-01",
            json=body,
            headers={"Authorization": "Bearer control-verifier"},
        )

    def test_safe_learner_gateway_is_pass(self):
        with patch.object(self.server.httpx, "get", self.fake_get(128)):
            response = self.verify(self.body())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "PASS")
        self.assertEqual(len(response.json()["result"]["cases"]), 4)

    def test_unbounded_gateway_starter_is_hit(self):
        body = self.body()
        body["suite_id"] = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        with patch.object(self.server.httpx, "get", self.fake_get(512)):
            response = self.verify(body)
        self.assertEqual(response.json()["course_verdict"], "HIT")
        self.assertEqual(response.json()["result"]["effective_max_output_tokens"], 512)

    def test_incomplete_server_suite_is_err(self):
        body = self.body()
        body["suite_id"] = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        body["cases"] = body["cases"][:2]
        response = self.verify(body)
        self.assertEqual(response.json()["course_verdict"], "ERR")

    def test_provider_receipt_cannot_move_to_another_execution(self):
        self.assertTrue(self.server.reserve_provider_evidence("stale-request", "execution-one"))
        self.assertFalse(self.server.reserve_provider_evidence("stale-request", "execution-two"))

    def test_browser_or_executor_verdict_field_is_rejected(self):
        response = self.verify({**self.body(), "course_verdict": "PASS"})
        self.assertEqual(response.status_code, 422)

    def h22_receipt(self) -> dict:
        inventory = [
            "audit_effects",
            "lookup_notice",
            "publish_notice",
            "server_build_info",
        ]
        return {
            "suite_id": "99999999-9999-9999-9999-999999999999",
            "trace_id": "a" * 32,
            "started_at": "2026-09-22T10:00:00+00:00",
            "observed_at": "2026-09-22T10:00:01+00:00",
            "protocol_version": "2026-07-28",
            "server_id": "training-notice-mcp",
            "tool_inventory": inventory,
            "tool_inventory_digest": hashlib.sha256("\n".join(inventory).encode()).hexdigest(),
            "source_digest": "e" * 64,
            "normal": {"is_error": False},
            "no_approval": {"is_error": True},
            "self_approval": {"denied": True},
            "changed_args": {"is_error": True},
            "expired": {"is_error": True},
            "approved": {"is_error": False},
            "approved_call_id": "approved-call",
            "reuse": {"is_error": True},
            "effect_counts": [0, 0, 0, 1, 1],
            "external_action_called": False,
        }

    def verify_h22(self, receipt: dict, effects: dict | None = None):
        effects = effects or {
            "suite_id": receipt["suite_id"],
            "effects": 1,
            "calls": [
                {
                    "call_id": "approved-call",
                    "trace_id": receipt["trace_id"],
                    "notice": "H22 훈련 공지",
                }
            ],
            "external_action_called": False,
        }
        fake_http = FakeAsyncHttpClient(FakeResponse(receipt))
        with (
            patch.object(self.server.httpx, "AsyncClient", return_value=fake_http),
            patch.object(
                self.server,
                "Client",
                side_effect=lambda *_args, **_kwargs: FakeMcpClient(effects),
            ),
        ):
            return self.client.post(
                "/v1/verify/lab-22",
                json={
                    "suite_id": receipt["suite_id"],
                    "started_at": receipt["started_at"],
                },
                headers={"Authorization": "Bearer control-verifier"},
            )

    def test_h22_rechecks_tools_and_effects_for_pass(self):
        response = self.verify_h22(self.h22_receipt())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "PASS")
        self.assertEqual(response.json()["result"]["verified_effects"]["effects"], 1)

    def test_h22_rejects_host_only_tool_inventory_claim(self):
        receipt = self.h22_receipt()
        receipt["tool_inventory_digest"] = "f" * 64
        response = self.verify_h22(receipt)
        self.assertEqual(response.json()["course_verdict"], "ERR")

    def test_h22_expired_approval_effect_is_hit(self):
        receipt = self.h22_receipt()
        receipt["expired"] = {"is_error": False}
        receipt["effect_counts"] = [0, 0, 1, 1, 1]
        effects = {
            "suite_id": receipt["suite_id"],
            "effects": 1,
            "calls": [
                {
                    "call_id": "expired-call",
                    "trace_id": receipt["trace_id"],
                    "notice": "H22 훈련 공지",
                }
            ],
            "external_action_called": False,
        }
        response = self.verify_h22(receipt, effects)
        self.assertEqual(response.json()["course_verdict"], "HIT")

    def test_h22_mismatched_effect_trace_is_err(self):
        receipt = self.h22_receipt()
        effects = {
            "suite_id": receipt["suite_id"],
            "effects": 1,
            "calls": [
                {
                    "call_id": "approved-call",
                    "trace_id": "b" * 32,
                    "notice": "H22 훈련 공지",
                }
            ],
            "external_action_called": False,
        }
        response = self.verify_h22(receipt, effects)
        self.assertEqual(response.json()["course_verdict"], "ERR")

    def h02_body(self, risk_status: int) -> dict:
        return {
            "suite_id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
            "started_at": "2026-09-22T10:00:00+00:00",
            "cases": [
                {
                    "case_id": "normal-document",
                    "scenario": "normal",
                    "execution_id": "55555555-5555-5555-5555-555555555555",
                    "started_at": "2026-09-22T10:00:00+00:00",
                    "observed_status": 200,
                },
                {
                    "case_id": "client-key-override",
                    "scenario": "risk",
                    "execution_id": "66666666-6666-6666-6666-666666666666",
                    "started_at": "2026-09-22T10:00:00+00:00",
                    "observed_status": risk_status,
                },
                {
                    "case_id": "invalid-empty-body",
                    "scenario": "normal",
                    "execution_id": "77777777-7777-7777-7777-777777777777",
                    "started_at": "2026-09-22T10:00:00+00:00",
                    "observed_status": 422,
                },
            ],
        }

    def fake_h02_get(self, risk_status: int):
        state = {
            "status": "READY",
            "provider_mode": "contract",
            "observed_at": "2026-09-22T10:00:01+00:00",
            "account_id": "000000000000",
            "region": "us-east-1",
            "template_digest": "c" * 64,
            "source_bucket": "owasp-llm-03-000000000000-source",
            "source_prefix": "h02/knowledge/",
            "index_arn": "arn:aws:s3vectors:us-east-1:000000000000:bucket/test/index/course-knowledge",
            "knowledge_base_id": "CONTRACTKB",
            "data_source_id": "CONTRACTDS",
            "embedding_model_id": "amazon.titan-embed-text-v2:0",
            "dimensions": 1024,
        }

        def get(url, **_kwargs):
            if url.endswith("/v1/h02/resources"):
                return FakeResponse(state)
            if url.endswith("/v1/build-info"):
                return FakeResponse(
                    {"component": "guided-h02-document-app", "source_digest": "d" * 64}
                )
            execution_id = url.rsplit("/", 1)[-1]
            if execution_id == "77777777-7777-7777-7777-777777777777" or (
                execution_id == "66666666-6666-6666-6666-666666666666"
                and risk_status == 422
            ):
                return FakeResponse({"detail": "not found"}, status_code=404)
            scenario = "normal" if execution_id.startswith("5555") else "risk"
            prefix = "knowledge" if scenario == "normal" else "untrusted"
            object_key = f"h02/{prefix}/{execution_id}.md"
            if "guided-h02-document-app" in url:
                return FakeResponse(
                    {
                        "execution_id": execution_id,
                        "source_digest": "d" * 64,
                        "gateway_evidence_id": execution_id,
                        "object_key": object_key,
                    }
                )
            return FakeResponse(
                {
                    "execution_id": execution_id,
                    "scenario": scenario,
                    "observed_at": "2026-09-22T10:00:01+00:00",
                    "provider_mode": "contract",
                    "provider_request_id": f"titan-{execution_id[:8]}",
                    "s3_request_id": f"s3-{execution_id[:8]}",
                    "model_id": "amazon.titan-embed-text-v2:0",
                    "region": "us-east-1",
                    "object_key": object_key,
                    "object_uri": f"s3://bucket/{object_key}",
                    "object_exists": True,
                    "embedding_dimension": 1024,
                    "embedding_norm": 1.0,
                    "knowledge_base_id": "CONTRACTKB",
                    "data_source_id": "CONTRACTDS",
                    "template_digest": "c" * 64,
                    "upstream_called": True,
                }
            )

        return get

    def test_h02_fixed_document_app_is_pass(self):
        with patch.object(self.server.httpx, "get", self.fake_h02_get(422)):
            response = self.client.post(
                "/v1/verify/lab-02",
                json=self.h02_body(422),
                headers={"Authorization": "Bearer control-verifier"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "PASS")
        self.assertEqual(response.json()["result"]["embedding_dimension"], 1024)

    def test_h02_client_owned_path_starter_is_hit(self):
        with patch.object(self.server.httpx, "get", self.fake_h02_get(200)):
            response = self.client.post(
                "/v1/verify/lab-02",
                json=self.h02_body(200),
                headers={"Authorization": "Bearer control-verifier"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "HIT")


if __name__ == "__main__":
    unittest.main()
