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
        os.environ["GUIDED_VERIFIER_LAB03_TOKEN"] = "verifier-lab03"
        os.environ["GUIDED_VERIFIER_LAB04_TOKEN"] = "verifier-lab04"
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

    def h03_body(self, suite_id: str) -> dict:
        return {
            "suite_id": suite_id,
            "execution_id": "88888888-8888-8888-8888-888888888888",
            "started_at": "2026-09-22T10:00:00+00:00",
        }

    def fake_h03_get(self, *, early_called: bool, mismatched_job: bool = False):
        execution_id = "88888888-8888-8888-8888-888888888888"
        job_id = "H03CURRENTJOB"
        old_uri = "s3://owasp-llm-03-h03-000000000000-source/h03/knowledge/revoked-policy.md"
        current_uri = "s3://owasp-llm-03-h03-000000000000-source/h03/knowledge/current-policy.md"
        digest = "3" * 64
        state = {
            "status": "CURRENT",
            "provider_mode": "contract",
            "observed_at": "2026-09-22T10:00:05+00:00",
            "account_id": "000000000000",
            "region": "us-east-1",
            "source_prefix": "h03/knowledge/",
            "template_digest": "4" * 64,
            "knowledge_base_id": "CONTRACTH03KB",
            "data_source_id": "CONTRACTH03DS",
            "old_source_uri": old_uri,
            "current_source_uri": current_uri,
            "old_source_exists": False,
            "current_source_exists": True,
            "indexed_documents": [
                {"status": "INDEXED", "source_uri": current_uri}
            ],
        }
        receipts = {
            "start": {
                "execution_id": execution_id,
                "observed_at": "2026-09-22T10:00:01+00:00",
                "source_digest": digest,
                "ingestion_job_id": job_id,
            },
            "early": {
                "execution_id": execution_id,
                "observed_at": "2026-09-22T10:00:02+00:00",
                "source_digest": digest,
                "ingestion_job_id": job_id,
                "observed_job_id": "ANOTHERJOB" if mismatched_job else job_id,
                "job_status": "IN_PROGRESS",
                "decision": "retrieve" if early_called else "wait",
                "retrieval_called": early_called,
                "retrieval_request_id": "h03-early-provider" if early_called else None,
            },
            "final": {
                "execution_id": execution_id,
                "observed_at": "2026-09-22T10:00:04+00:00",
                "source_digest": digest,
                "ingestion_job_id": job_id,
                "observed_job_id": job_id,
                "job_status": "COMPLETE",
                "decision": "retrieve",
                "retrieval_called": True,
                "retrieval_request_id": "h03-final-provider",
            },
        }
        final = {
            "execution_id": execution_id,
            "phase": "final",
            "provider_mode": "contract",
            "provider_request_id": "h03-final-provider",
            "observed_at": "2026-09-22T10:00:04+00:00",
            "ingestion_job_id": job_id,
            "job_status_at_retrieval": "COMPLETE",
            "knowledge_base_id": "CONTRACTH03KB",
            "data_source_id": "CONTRACTH03DS",
            "template_digest": "4" * 64,
            "source_uris": [current_uri],
            "document_ids": ["current-document"],
        }
        early = {
            "execution_id": execution_id,
            "phase": "early",
            "provider_mode": "contract",
            "provider_request_id": "h03-early-provider",
            "observed_at": "2026-09-22T10:00:02+00:00",
            "ingestion_job_id": job_id,
            "job_status_at_retrieval": "IN_PROGRESS",
            "knowledge_base_id": "CONTRACTH03KB",
            "data_source_id": "CONTRACTH03DS",
            "template_digest": "4" * 64,
            "source_uris": [old_uri],
            "document_ids": ["revoked-document"],
        }

        def get(url, **_kwargs):
            if url.endswith("/v1/build-info"):
                return FakeResponse(
                    {"component": "guided-h03-sync-app", "source_digest": digest}
                )
            if url.endswith("/v1/h03/resources"):
                return FakeResponse(state)
            if "/v1/receipts/" in url:
                return FakeResponse(receipts[url.rsplit("/", 1)[-1]])
            if url.endswith(f"/v1/h03/jobs/{job_id}"):
                return FakeResponse(
                    {"ingestion_job_id": job_id, "status": "COMPLETE"}
                )
            if url.endswith(f"/v1/h03/retrievals/{execution_id}/final"):
                return FakeResponse(final)
            if url.endswith(f"/v1/h03/retrievals/{execution_id}/early"):
                return FakeResponse(early) if early_called else FakeResponse({}, 404)
            raise AssertionError(f"unexpected H03 URL: {url}")

        return get

    def verify_h03(self, suite_id: str, *, early_called: bool, mismatched_job: bool = False):
        with patch.object(
            self.server.httpx,
            "get",
            self.fake_h03_get(
                early_called=early_called, mismatched_job=mismatched_job
            ),
        ):
            return self.client.post(
                "/v1/verify/lab-03",
                json=self.h03_body(suite_id),
                headers={"Authorization": "Bearer control-verifier"},
            )

    def test_h03_starter_retrieves_revoked_document_as_hit(self):
        response = self.verify_h03(
            "03000000-0000-0000-0000-000000000001", early_called=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "HIT")
        self.assertEqual(
            response.json()["stage_calls"][2]["outcome"], "revoked-source-hit"
        )

    def test_h03_current_job_complete_gate_is_pass(self):
        response = self.verify_h03(
            "03000000-0000-0000-0000-000000000002", early_called=False
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "PASS")
        self.assertEqual(
            response.json()["stage_calls"][2]["outcome"],
            "blocked-before-retrieval",
        )

    def test_h03_mismatched_observed_job_is_err(self):
        response = self.verify_h03(
            "03000000-0000-0000-0000-000000000003",
            early_called=False,
            mismatched_job=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "ERR")

    def h04_body(self, suite_id: str) -> dict:
        case_ids = ["apply-normal", "apply-risk", "converse-normal", "converse-risk"]
        return {
            "suite_id": suite_id,
            "started_at": "2026-09-23T10:00:00+00:00",
            "cases": [
                {
                    "case_id": case_id,
                    "execution_id": f"04000000-0000-0000-0000-{index:012d}",
                    "started_at": "2026-09-23T10:00:00+00:00",
                }
                for index, case_id in enumerate(case_ids, 1)
            ],
        }

    def fake_h04_get(
        self,
        *,
        protected: bool,
        include_trace: bool = True,
        normal_connected: bool | None = None,
        risk_model_called: bool = True,
    ):
        digest = "4" * 64
        state = {
            "status": "READY",
            "provider_mode": "contract",
            "observed_at": "2026-09-23T10:00:01+00:00",
            "account_id": "000000000000",
            "region": "us-east-1",
            "guardrail_id": "CONTRACTH04GR",
            "guardrail_version": "DRAFT",
            "guardrail_name": "owasp-llm-03-h04-000000000000",
            "template_digest": "a" * 64,
            "pii_type": "EMAIL",
            "input_enabled": False,
            "output_enabled": True,
            "output_action": "ANONYMIZE",
        }
        case_ids = ["apply-normal", "apply-risk", "converse-normal", "converse-risk"]
        execution_to_case = {
            f"04000000-0000-0000-0000-{index:012d}": case_id
            for index, case_id in enumerate(case_ids, 1)
        }

        def provider(case_id: str, execution_id: str) -> dict:
            common = {
                "execution_id": execution_id,
                "case_id": case_id,
                "provider_mode": "contract",
                "provider_request_id": f"h04-{case_id}",
                "observed_at": "2026-09-23T10:00:01+00:00",
                "template_digest": "a" * 64,
            }
            if case_id == "apply-normal":
                return {**common, "operation": "apply_guardrail", "guardrail_id": "CONTRACTH04GR", "guardrail_version": "DRAFT", "action": "NONE", "outputs": [], "pii_actions": [], "model_called": False}
            if case_id == "apply-risk":
                return {
                    **common,
                    "operation": "apply_guardrail",
                    "guardrail_id": "CONTRACTH04GR",
                    "guardrail_version": "DRAFT",
                    "action": "GUARDRAIL_INTERVENED",
                    "outputs": [{"text": "담당자 이메일은 {EMAIL} 입니다."}],
                    "pii_actions": [{"type": "EMAIL", "action": "ANONYMIZED"}],
                    "model_called": False,
                }
            if case_id == "converse-normal":
                return {
                    **common,
                    "operation": "converse",
                    "model_id": "us.amazon.nova-lite-v1:0",
                    "model_called": True,
                    "output_text": "고객지원 운영 시간 안내",
                    "usage": {"outputTokens": 12},
                    "guardrail_config": {"guardrailIdentifier": "CONTRACTH04GR", "guardrailVersion": "DRAFT"} if (protected if normal_connected is None else normal_connected) else None,
                    "pii_actions": [],
                    "stop_reason": "end_turn",
                }
            return {
                **common,
                "operation": "converse",
                "model_id": "us.amazon.nova-lite-v1:0",
                "model_called": risk_model_called,
                "output_text": "담당자 이메일은 {EMAIL} 입니다." if protected else "담당자 이메일은 learner@example.com 입니다.",
                "usage": {"outputTokens": 12},
                "guardrail_config": {"guardrailIdentifier": "CONTRACTH04GR", "guardrailVersion": "DRAFT"} if protected else None,
                "pii_actions": ([{"type": "EMAIL", "action": "ANONYMIZED"}] if protected and include_trace else []),
                "stop_reason": "end_turn",
            }

        def get(url, **_kwargs):
            if url.endswith("/v1/h04/resources"):
                return FakeResponse(state)
            if url.endswith("/v1/build-info"):
                return FakeResponse({"component": "guided-h04-guardrail-app", "source_digest": digest})
            execution_id = url.rsplit("/", 1)[-1]
            case_id = execution_to_case[execution_id]
            record = provider(case_id, execution_id)
            if "/v1/receipts/" in url:
                return FakeResponse(
                    {
                        "execution_id": execution_id,
                        "case_id": case_id,
                        "source_digest": digest,
                        "gateway_evidence_id": execution_id,
                        "provider_request_id": record["provider_request_id"],
                    }
                )
            return FakeResponse(record)

        return get

    def verify_h04(
        self,
        suite_id: str,
        *,
        protected: bool,
        include_trace: bool = True,
        normal_connected: bool | None = None,
        risk_model_called: bool = True,
    ):
        with patch.object(
            self.server.httpx,
            "get",
            self.fake_h04_get(
                protected=protected,
                include_trace=include_trace,
                normal_connected=normal_connected,
                risk_model_called=risk_model_called,
            ),
        ):
            return self.client.post(
                "/v1/verify/lab-04",
                json=self.h04_body(suite_id),
                headers={"Authorization": "Bearer control-verifier"},
            )

    def test_h04_starter_raw_email_is_hit(self):
        response = self.verify_h04(
            "04000000-0000-0000-0001-000000000001", protected=False
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "HIT")
        self.assertEqual(response.json()["stage_calls"][2]["outcome"], "raw-email-exposed")

    def test_h04_connected_guardrail_is_pass(self):
        response = self.verify_h04(
            "04000000-0000-0000-0001-000000000002", protected=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "PASS")
        self.assertIn("{EMAIL}", response.json()["result"]["output_text"])

    def test_h04_missing_guardrail_trace_is_err(self):
        response = self.verify_h04(
            "04000000-0000-0000-0001-000000000003",
            protected=True,
            include_trace=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "ERR")

    def test_h04_risk_only_connection_is_err(self):
        response = self.verify_h04(
            "04000000-0000-0000-0001-000000000005",
            protected=True,
            normal_connected=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "ERR")

    def test_h04_fake_model_call_is_not_hit(self):
        response = self.verify_h04(
            "04000000-0000-0000-0001-000000000006",
            protected=False,
            risk_model_called=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["course_verdict"], "ERR")

    def test_h04_browser_verdict_field_is_rejected(self):
        response = self.client.post(
            "/v1/verify/lab-04",
            json={**self.h04_body("04000000-0000-0000-0001-000000000004"), "course_verdict": "PASS"},
            headers={"Authorization": "Bearer control-verifier"},
        )
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
