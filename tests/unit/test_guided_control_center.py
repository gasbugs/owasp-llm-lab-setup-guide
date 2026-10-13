"""Tenant 03 vertical slice security and deployment contracts."""

from __future__ import annotations

import importlib.util
import html as html_module
import json
import os
import re
import sys
import unittest
import subprocess
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
        if "/v1/resource-progress/" in url:
            parts = url.split("/")
            return FakeResponse({"practice_id": parts[-2], "operation_id": parts[-1],
                                 "current": 3, "total": 11, "state": "running",
                                 "title": "S3 원문 저장소 준비", "description": "문서 원문 저장소를 준비합니다."})
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
        if "/v1/h08/suites/" in url and "/cases/" in url and url.endswith("/close"):
            parts=url.split("/")
            return FakeResponse({"suite_id":parts[-4],"case_id":parts[-2],"case_closed_at":"2026-09-23T10:00:01+00:00"})
        if url.endswith("/v1/verify/h08-case"):
            return FakeResponse({"case_id":json["case_id"],"status":"PASS","course_verdict":"PASS","case_verified":True,"task_completed":False})
        if "/v1/h08/suites/" in url and url.endswith("/close"):
            return FakeResponse(
                {"suite_id": url.rsplit("/", 2)[-2], "closed_at": "2026-09-24T10:00:01+00:00"}
            )
        if "guided-h09-delivery-sink" in url and "/cases/" in url and url.endswith("/close"):
            parts=url.split("/")
            return FakeResponse({"suite_id":parts[-4],"case_id":parts[-2],"case_closed_at":"2026-09-23T10:00:01+00:00"})
        if url.endswith("/v1/verify/h10-case"):
            return FakeResponse({"case_id":json["case_id"],"status":"PASS","course_verdict":"PASS","case_verified":True,"task_completed":False})
        if url.endswith("/v1/verify/h09-case"):
            return FakeResponse({"case_id":json["case_id"],"status":"PASS","course_verdict":"PASS","case_verified":True,"task_completed":False})
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
        if "/v1/h07/suites/" in url and "/cases/" in url and url.endswith("/close"):
            parts=url.split("/")
            return FakeResponse({"suite_id":parts[-4],"case_id":parts[-2],"case_closed_at":"2026-09-23T10:00:01+00:00"})
        if url.endswith("/v1/verify/h07-case"):
            return FakeResponse({"case_id":json["case_id"],"status":"PASS","course_verdict":"PASS","case_verified":True,"task_completed":False})
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
            if not re.fullmatch(r"[a-z0-9-]{1,64}", json.get("client_id", "")):
                return FakeResponse({"detail": "missing or invalid client_id"}, status_code=422)
            message, tokens = json.get("message"), json.get("max_output_tokens")
            if not isinstance(message, str) or not message.strip() or len(message) > 4000 or type(tokens) is not int or not 1 <= tokens <= 512 or "model" in json:
                return FakeResponse({"detail": "invalid request"}, status_code=422)
            if message.startswith("예산을 초과하는"):
                return FakeResponse({"detail": "hourly output-token budget exhausted"}, status_code=429)
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
        if "/v1/resource-lifecycle/" in url:
            problem = url.split("/")[-2]
            return FakeResponse({"practice_id": problem, "operation_id": json["operation_id"], "state": "deleted"})
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
        if url.endswith(("/v1/run","/v1/run-case")):
            if "guided-h02-document-app" in url or "guided-h03-sync-app" in url:
                return FakeResponse({"suite_id": json["suite_id"]})
            if "execution_ids" in json:
                return FakeResponse({"suite_id":json["suite_id"]})
            if "cases" in json:
                if json["cases"] and "content_safety_capability" in json["cases"][0]:
                    if self.h07_run_request_error:
                        raise httpx.ConnectError("H07 learner unavailable", request=httpx.Request("POST", url))
                    if self.h07_run_status != 200:
                        return FakeResponse({"detail": "H07 learner failed"}, status_code=self.h07_run_status)
                return FakeResponse({"suite_id": json["suite_id"], "source_digest": "a" * 64})
            return FakeResponse({"execution_id": json["execution_id"]})
        if url.endswith("/v1/verify/h06-case"):
            return FakeResponse({"case_id":json["case_id"],"status":"PASS","case_verified":True,"task_completed":False})
        if url.endswith("/v1/verify/lab-05-case"):
            return FakeResponse({"case_id":json["cases"][0]["case_id"],"status":"PASS","case_verified":True,"task_completed":False})
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


class SequentialFailureClient(FakeAsyncClient):
    async def post(self,url,*,json=None,headers):
        self.calls.append({'url':url,'json':json,'headers':headers})
        if '/v1/verify/' not in url:return FakeResponse({'suite_id':json['suite_id']})
        part=url.rsplit('/',1)[-1];number=part.split('-')[0][1:]
        activity=('H' if number in ('21','22') else 'P')+number
        return FakeResponse({'activity_id':activity,'execution_id':json['suite_id'],'started_at':json['started_at'],
            'verified_by':'guided-evidence-verifier','course_verdict':'ERR','case_verified':False,
            'task_completed':False,'reason':'fixture incomplete','result':{}})


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

    def test_native_initialization_diagnosis_reaches_grading_case(self):
        original=FakeAsyncClient.post
        async def post(client,url,**kwargs):
            if url.endswith("/v1/run-case") and "guided-h07" in url:
                return FakeResponse({"detail":{"diagnosis":{"cause":"등록되지 않은 input Rail: check input safety", "field":"rails.input.flows", "model_calls":"0회 — 초기화 중단", "evidence":"실제 설정 검증 오류"}}},500)
            return await original(client,url,**kwargs)
        with patch.object(FakeAsyncClient,"post",post),patch.object(self.server.httpx,"AsyncClient",FakeAsyncClient):
            response=self.client.post("/api/practice/P07/verify",headers=self.headers)
        def hints(value):
            if isinstance(value,dict):
                if "diagnosis" in value:yield value["diagnosis"]
                for key,child in value.items():
                    if key!="diagnosis":yield from hints(child)
            elif isinstance(value,list):
                for child in value:yield from hints(child)
        observed=list(hints(response.json()))
        self.assertTrue(observed,response.text)
        for hint in observed:
            self.assertIn("check input safety",hint["cause"])
            self.assertTrue(hint["model_calls"].startswith("0회"))
            self.assertTrue(hint["log_command"].endswith("guided-h07-content-safety"))

    def test_all_problem_surfaces_have_guidance_and_apply_commands(self):
        page = self.home.text
        for number in range(2, 23):
            start = page.index(f'id="h{number:02d}-work"')
            following = re.search(r'id="h\d{2}-work"', page[start + 20:])
            end = start + 20 + following.start() if following else page.index('<section class="inspection"', start)
            section = page[start:end]
            with self.subTest(problem=number):
                self.assertIn('class="mission-brief"', section)
                self.assertIn('미션 해결 조건', section)
                self.assertIn('코드 적용하기', section)
                self.assertIn('docker compose', section)
                self.assertIn('--force-recreate', section)
                self.assertIn('미션 채점', section)

    def test_problem_conditions_are_direct_and_include_required_values(self):
        page = self.home.text
        for fragment in (
            "P01·P02·P22의 source",
            "P05·P06의 설정이나 실행 상태",
            "P07의 설정과 실행 결과",
            "P17~P19의 코드나 실행 기록",
            "다른 문제의 실행을 막지 않습니다",
            "P01을 풀지 않아도 시작할 수 있습니다",
        ):
            self.assertNotIn(fragment, page)
        for fragment in (
            "run.soft_probe_prompt_cap: 1",
            "MAX_TURNS = 3",
            "support-agent",
            "training-notice-mcp",
            "Tool <code>2</code>회",
            "결과 <code>160</code> bytes",
            "timeout <code>250</code> ms",
        ):
            self.assertIn(fragment, page)

    def test_reload_preserves_verified_p00_session_and_token(self):
        token = self.bootstrap["p00_submission_token"]
        result = self.client.post("/api/practice/P00/check", headers={"Authorization": "Bearer " + token},
            json={"message": "계정 보안을 위한 조언을 한 문장으로 알려 주세요.", "max_tokens": 64}).json()
        self.assertTrue(result["completed"])
        self.assertEqual(len(result["cases"]), 4)
        self.assertTrue(all(case["case_verified"] for case in result["cases"]))
        cookie = self.client.cookies.get("guided_session")
        self.client.get("/")
        self.assertEqual(self.client.cookies.get("guided_session"), cookie)
        self.assertEqual(self.client.get("/api/bootstrap").json()["p00_submission_token"], token)
        self.assertEqual(self.client.get("/api/practice/P00/result").json(), result)

    def test_p00_independent_request_checks(self):
        headers = {"Authorization": "Bearer " + self.bootstrap["p00_submission_token"]}
        valid = {"message": "계정 보안을 위한 조언을 한 문장으로 알려 주세요.", "max_tokens": 64}
        self.assertNotIn("received", self.client.get("/api/practice/P00/result").json())
        for document, expected in [("{}", False), ("{", False), (json.dumps(valid), True),
                                   (json.dumps(dict(valid, max_tokens="64")), False),
                                   (json.dumps(dict(valid, completed=True)), False)]:
            response = self.client.post("/api/practice/P00/check", headers=headers, content=document)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["completed"], expected)
            self.assertEqual(self.client.get("/api/practice/P00/result").json(), response.json())
        malformed = self.client.post("/api/practice/P00/check", headers=headers, content="{").json()
        self.assertFalse(malformed["cases"][0]["case_verified"])
        self.assertTrue(all(case["status"] == "미실행" for case in malformed["cases"][1:]))
        wrong_type = self.client.post("/api/practice/P00/check", headers=headers, json=dict(valid, max_tokens="64")).json()
        self.assertEqual([case["case_verified"] for case in wrong_type["cases"]], [True, True, True, False])
        self.assertEqual(self.client.post("/api/practice/P00/check", content="{}").status_code, 401)
        self.assertEqual(self.client.post("/api/practice/P00/check", headers=headers, content=" " * 4097).status_code, 413)
        other = TestClient(self.server.app)
        other.get("/")
        self.assertNotIn("received", other.get("/api/practice/P00/result").json())
        self.assertEqual(TestClient(self.server.app).get("/api/practice/P00/result").status_code, 401)
        self.assertNotIn("tutorial-request", self.home.text)
        self.assertIn("tutorial-submit-command", self.home.text)

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
        self.assertEqual(self.bootstrap["course"]["hands_on"], 23)
        self.assertEqual(self.bootstrap["course"]["implemented_hands_on"], [f"H{number:02d}" for number in range(1, 24)])
        self.assertEqual(self.bootstrap['workspace'], 'practice')
        p02 = next(item for item in self.bootstrap["learner_apps"] if item["hands_on_id"] == "H02")
        self.assertEqual(p02["source_path"], "llm-security-control-plane/guided-labs/h02-document-ingestion/learner.py")
        self.assertEqual(self.bootstrap['course']['practices'], 23)
        self.assertEqual(self.bootstrap['course']['practice_ids'], [f'P{n:02d}' for n in range(1, 24)])
        self.assertEqual(self.bootstrap['course']['execution_ids'], {f'P{n:02d}': f'H{n:02d}' for n in range(1, 24)})
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

    def test_p03_direct_search_forwards_only_query_without_grading(self):
        class SearchClient(FakeAsyncClient):
            async def post(self, url, *, json=None, headers):
                self.calls.append({"url": url, "json": json, "headers": headers})
                return FakeResponse({"practice_id": "P03", "graded": False, "query": json["query"], "execution": {}})
        with patch.object(self.server.httpx, "AsyncClient", SearchClient):
            response = self.client.post("/api/knowledge/search", headers=self.headers, json={"query": "계정 접근 절차"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["graded"])
        self.assertEqual(len(FakeAsyncClient.calls), 1)
        self.assertTrue(FakeAsyncClient.calls[0]["url"].endswith("/v1/search"))
        self.assertEqual(FakeAsyncClient.calls[0]["json"], {"query": "계정 접근 절차"})
        self.assertEqual(self.client.post("/api/knowledge/search", headers=self.headers,
            json={"query": "검색", "knowledge_base_id": "spoof"}).status_code, 422)
        self.assertEqual(self.client.post("/api/knowledge/search", headers=self.headers, json={"query": " "}).status_code, 422)
        self.assertEqual(self.client.post("/api/knowledge/search", json={"query": "검색"}).status_code, 403)

    def test_session_refresh_preserves_identity_and_tokens_with_persistent_cookie(self):
        cookie = self.client.cookies.get("guided_session")
        _, state = self.server.session_from_cookie(cookie)
        before = dict(state)
        response = self.client.post("/api/session/refresh", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.cookies.get("guided_session"), cookie)
        self.assertEqual(state, before)
        self.assertIn("Max-Age=604800", response.headers["set-cookie"])
        self.assertIn("HttpOnly", response.headers["set-cookie"])
        self.assertEqual(self.client.post("/api/session/refresh").status_code, 403)
        other = TestClient(self.server.app)
        self.assertEqual(other.post("/api/session/refresh", headers=self.headers).status_code, 401)
        other.close()

    def test_server_session_loss_reconnects_same_signed_browser_identity(self):
        cookie = self.client.cookies.get("guided_session")
        sid, state = self.server.session_from_cookie(cookie)
        csrf = state["csrf"]
        self.server.SESSIONS.pop(sid)
        self.assertEqual(self.client.post("/api/session/refresh", headers=self.headers).status_code, 401)
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.cookies.get("guided_session"), cookie)
        recovered = self.client.get("/api/bootstrap").json()
        self.assertNotEqual(recovered["csrf_token"], csrf)
        self.assertEqual(self.client.post("/api/session/refresh", headers={
            "Origin": "http://testserver", "X-CSRF-Token": recovered["csrf_token"]}).status_code, 200)

    def test_p01_case_progress_is_session_owned_and_reports_actual_http(self):
        self.assertEqual(self.client.get("/api/test-progress/P01").json()["phase"], "idle")
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            self.client.post("/api/practice/P01/verify", headers=self.headers)
        progress = self.client.get("/api/test-progress/P01").json()
        self.assertEqual(progress["phase"], "finished")
        self.assertEqual(len(progress["cases"]), 23)
        for case in progress["cases"]:
            self.assertEqual(case["status"], "PASS")
            self.assertEqual(case["observed_status"], case["expected_status"])
        other = TestClient(self.server.app)
        self.assertEqual(other.get("/api/test-progress/P01").status_code, 401)
        other.get("/")
        self.assertEqual(other.get("/api/test-progress/P01").json()["phase"], "idle")

    def test_p02_progress_is_session_owned_and_preserves_verified_failure(self):
        self.assertEqual(self.client.get("/api/test-progress/P02").json()["phase"], "idle")
        suite = "progress-fixture"
        cookie = self.client.cookies.get("guided_session")
        _, state = self.server.session_from_cookie(cookie)
        state["p02_case_progress"] = {"suite_id": suite, "phase": "running", "cases": [], "total": 22}
        class ProgressClient(FakeAsyncClient):
            async def get(self, url, *, headers):
                if "/v1/progress/p02/" in url:
                    return FakeResponse({"suite_id": suite, "phase": "finished", "total": 22,
                        "cases": [{"case_id": "first", "case_verified": True}, {"case_id": "second", "status": "ERR"}], "current_case": None})
                return FakeResponse({"suite_id": suite, "phase": "verifying", "total": 22,
                    "cases": [], "current_case": None})
        with patch.object(self.server.httpx, "AsyncClient", ProgressClient):
            progress = self.client.get("/api/test-progress/P02").json()
            self.assertEqual(progress["cases"][0]["case_verified"], True)
            self.assertEqual(progress["cases"][1]["status"], "ERR")
            state["p02_case_progress"].update(phase="finished", verdict="ERR")
            self.assertEqual(self.client.get("/api/test-progress/P02").json()["cases"], progress["cases"])
        other = TestClient(self.server.app)
        self.assertEqual(other.get("/api/test-progress/P02").status_code, 401)
        other.get("/")
        self.assertIsNone(other.get("/api/test-progress/P02").json()["suite_id"])
        other.close()

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
        expected = {f"/api/practice/P{number:02d}/verify" for number in range(1, 24)}
        expected.update(f"/api/practice/P{number:02d}/provision" for number in (2, 3, 4))
        expected.update(f"/api/practice/P{number:02d}/delete-resources" for number in (2, 3, 4))
        expected.update({"/api/practice/P01/chat", "/api/practice/P23/chat"})
        actual = {path for path in routes if path.startswith("/api/practice/")}
        self.assertEqual(actual, expected | {"/api/practice/P00/check", "/api/practice/P00/result", "/api/practice/P04/chat"})
        self.assertEqual(len(legacy), len(expected) - 5)
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
                if not route.path.startswith("/api/practice/") or route.path.startswith("/api/practice/P00/"):
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
        for activity in ("P00", "P24", "P1", "H01", "p01"):
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
        self.assertEqual(len(FakeAsyncClient.calls), 24)
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
        self.assertEqual(len(FakeAsyncClient.calls), 24)
        normal_call, risk_call = FakeAsyncClient.calls[:2]
        invalid_call, override_call, verifier_call = FakeAsyncClient.calls[7], FakeAsyncClient.calls[20], FakeAsyncClient.calls[-1]
        self.assertEqual(normal_call["json"]["max_output_tokens"], 64)
        self.assertEqual(risk_call["json"]["max_output_tokens"], 512)
        self.assertEqual(invalid_call["json"]["message"], "")
        self.assertEqual(override_call["json"]["model"], "client-selected-model")
        self.assertEqual(verifier_call["json"]["suite_kind"], "hands_on")
        self.assertEqual(len(verifier_call["json"]["cases"]), 23)
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
        self.assertRegex(request["client_id"], r"^chat-[a-f0-9]{32}$")

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
        self.assertEqual(response.json()["activity_id"], "P02")
        self.assertTrue(response.json()["resource_ready"])
        self.assertFalse(response.json()["task_completed"])
        self.assertNotIn("course_verdict", response.json())

    def test_resource_progress_is_current_session_and_mission_owned(self):
        self.assertEqual(TestClient(self.server.app).get("/api/resource-progress/P02").status_code, 401)
        self.assertEqual(self.client.get("/api/resource-progress/P02").json()["state"], "idle")
        _, data = self.server.session_from_cookie(self.client.cookies.get("guided_session"))
        data["resource_operation"] = {"problem": "P02", "operation_id": "own-operation"}
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
            row = self.client.get("/api/resource-progress/P02").json()
            other = self.client.get("/api/resource-progress/P03").json()
        self.assertEqual(row["current"], 3)
        self.assertEqual(row["total"], 11)
        self.assertEqual(row["operation_id"], "own-operation")
        self.assertEqual(other, {"state": "idle"})

    def test_resource_deletion_is_authenticated_server_owned_and_not_grading(self):
        for problem in ("P02", "P03", "P04"):
            route = f"/api/practice/{problem}/delete-resources"
            self.assertEqual(self.client.post(route).status_code, 403)
            self.assertEqual(self.client.post(route, json={"bucket": "foreign"}, headers=self.headers).status_code, 422)
            with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
                response = self.client.post(route, headers=self.headers)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json()["resource_deleted"])
            self.assertFalse(response.json()["task_completed"])
            self.assertNotIn("course_verdict", response.json())

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
        for number in range(1, 24):
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
            item for item in FakeAsyncClient.calls if item["url"].endswith("/v1/verify/lab-05")
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

    def test_h05_stops_before_next_case_and_topical_when_independent_check_fails(self):
        original=FakeAsyncClient.post
        async def post(client,url,**kwargs):
            if url.endswith("/v1/verify/lab-05-case"):
                FakeAsyncClient.calls.append({"url":url,**kwargs})
                return FakeResponse({"case_id":kwargs["json"]["cases"][0]["case_id"],"case_verified":False,"status":"ERR","reason":"raw evidence mismatch"})
            return await original(client,url,**kwargs)
        FakeAsyncClient.calls.clear()
        with patch.object(self.server.httpx,"AsyncClient",FakeAsyncClient),patch.object(FakeAsyncClient,"post",post):
            response=self.client.post("/api/practice/P05/verify",headers=self.headers)
        self.assertEqual(response.status_code,200,response.text)
        self.assertFalse(response.json()["task_completed"])
        executions=[call for call in FakeAsyncClient.calls if call["url"].endswith("/v1/run")]
        self.assertEqual([call["json"]["case_id"] for call in executions],["contact-exact"])
        self.assertFalse(any(call["url"].endswith("/v1/evaluate") for call in FakeAsyncClient.calls))
        cases=response.json()["result"]["cases"]
        self.assertEqual([case["status"] for case in cases],["ERR","미실행","미실행","미실행"])

    def test_h11_case_verdict_stops_future_search_and_final_grade(self):
        original=FakeAsyncClient.post
        for result_status in ("HIT", "ERR"):
            async def post(client,url,**kwargs):
                if url.endswith("/v1/run-case"):
                    FakeAsyncClient.calls.append({"url":url,**kwargs})
                    return FakeResponse({"suite_id":kwargs["json"]["suite_id"]})
                if url.endswith("/v1/verify/h11-case"):
                    FakeAsyncClient.calls.append({"url":url,**kwargs})
                    cid=kwargs["json"]["case_id"]
                    status="PASS" if cid=="normal-approved" else result_status
                    return FakeResponse({"case_id":cid,"status":status,"course_verdict":status,"case_verified":status=="PASS"})
                return await original(client,url,**kwargs)
            FakeAsyncClient.calls.clear()
            with patch.object(self.server.httpx,"AsyncClient",FakeAsyncClient),patch.object(FakeAsyncClient,"post",post):
                response=self.client.post("/api/practice/P11/verify",headers=self.headers)
            self.assertEqual(response.status_code,200,response.text)
            self.assertFalse(response.json()["task_completed"])
            self.assertEqual([r["status"] for r in response.json()["result"]["cases"]],["PASS",result_status,"미실행","미실행"])
            self.assertEqual([c["json"]["case_id"] for c in FakeAsyncClient.calls if c["url"].endswith("/v1/run-case")],["normal-approved","client-self-approval"])
            self.assertFalse(any(c["url"].endswith("/v1/verify/h11") for c in FakeAsyncClient.calls))

    def test_h06_transport_error_marks_first_case_err_and_later_cases_unexecuted(self):
        original=FakeAsyncClient.post
        async def post(client,url,**kwargs):
            if url.endswith("/v1/run-case"):
                FakeAsyncClient.calls.append({"url":url,**kwargs})
                raise httpx.ConnectError("worker unavailable",request=httpx.Request("POST",url))
            return await original(client,url,**kwargs)
        FakeAsyncClient.calls.clear()
        with patch.object(self.server.httpx,"AsyncClient",FakeAsyncClient),patch.object(FakeAsyncClient,"post",post):
            response=self.client.post("/api/practice/P06/verify",headers=self.headers)
        self.assertEqual(response.status_code,200,response.text)
        self.assertFalse(response.json()["task_completed"])
        self.assertEqual(response.json()["verified_by"],"guided-control-center")
        self.assertFalse(any(stage["stage"]=="action_policy" for stage in response.json()["stage_calls"]))
        self.assertEqual([row["status"] for row in response.json()["result"]["cases"]],["ERR","미실행","미실행","미실행"])
        self.assertEqual(len([call for call in FakeAsyncClient.calls if call["url"].endswith("/v1/run-case")]),1)
        self.assertFalse(any("/v1/verify/h06" in call["url"] for call in FakeAsyncClient.calls))

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
            if item["url"].endswith("/v1/run-case") and "cases" in item["json"]
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
        learner_index = next(index for index, url in enumerate(urls) if url.endswith("/v1/run-case"))
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

    def test_h08_failed_case_never_runs_next_and_closes_unused_suite_grants(self):
        original=FakeAsyncClient.post
        async def post(client,url,**kwargs):
            if url.endswith("/v1/verify/h08-case"):
                FakeAsyncClient.calls.append({"url":url,**kwargs})
                return FakeResponse({"case_id":kwargs["json"]["case_id"],"status":"ERR","course_verdict":"ERR","case_verified":False,"reason":"classifier schema invalid"})
            return await original(client,url,**kwargs)
        with patch.object(self.server.httpx,"AsyncClient",FakeAsyncClient),patch.object(FakeAsyncClient,"post",post):
            response=self.client.post("/api/practice/P08/verify",headers=self.headers)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual([row["status"] for row in response.json()["result"]["cases"]],["ERR","미실행","미실행","미실행"])
        self.assertFalse(response.json()["task_completed"])
        self.assertEqual(len([call for call in FakeAsyncClient.calls if call["url"].endswith("/v1/run-case")]),1)
        self.assertTrue(any(call["url"].endswith("/close") and "/cases/" not in call["url"] for call in FakeAsyncClient.calls))
        self.assertFalse(any(call["url"].endswith("/v1/verify/h08") for call in FakeAsyncClient.calls))

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
            if item["url"].endswith("/v1/run-case")
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

    def test_h09_failed_case_never_runs_next_and_closes_unused_suite_grants(self):
        original=FakeAsyncClient.post
        async def post(client,url,**kwargs):
            if url.endswith("/v1/verify/h09-case"):
                FakeAsyncClient.calls.append({"url":url,**kwargs})
                return FakeResponse({"case_id":kwargs["json"]["case_id"],"status":"ERR","course_verdict":"ERR","case_verified":False,"reason":"classifier schema invalid"})
            return await original(client,url,**kwargs)
        with patch.object(self.server.httpx,"AsyncClient",FakeAsyncClient),patch.object(FakeAsyncClient,"post",post):
            response=self.client.post("/api/practice/P09/verify",headers=self.headers)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual([row["status"] for row in response.json()["result"]["cases"]],["ERR","미실행","미실행","미실행"])
        self.assertFalse(response.json()["task_completed"])
        self.assertEqual(len([call for call in FakeAsyncClient.calls if call["url"].endswith("/v1/run-case")]),1)
        self.assertTrue(any(call["url"].endswith("/close") and "/cases/" not in call["url"] for call in FakeAsyncClient.calls))
        self.assertFalse(any(call["url"].endswith("/v1/verify/h09") for call in FakeAsyncClient.calls))

    def test_h10_failed_case_never_runs_next(self):
        original=FakeAsyncClient.post
        async def post(client,url,**kwargs):
            if url.endswith("/v1/verify/h10-case"):
                FakeAsyncClient.calls.append({"url":url,**kwargs})
                return FakeResponse({"case_id":kwargs["json"]["case_id"],"status":"ERR","course_verdict":"ERR","case_verified":False,"reason":"classifier schema invalid"})
            return await original(client,url,**kwargs)
        with patch.object(self.server.httpx,"AsyncClient",FakeAsyncClient),patch.object(FakeAsyncClient,"post",post):
            response=self.client.post("/api/practice/P10/verify",headers=self.headers)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual([row["status"] for row in response.json()["result"]["cases"]],["ERR","미실행","미실행","미실행"])
        self.assertFalse(response.json()["task_completed"])
        self.assertEqual(len([call for call in FakeAsyncClient.calls if call["url"].endswith("/v1/run-case")]),1)
        self.assertFalse(any(call["url"].endswith("/v1/verify/h10") for call in FakeAsyncClient.calls))

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
            and item["url"].endswith("/v1/run-case")
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

    def test_h07_failed_case_never_runs_next_and_closes_unused_suite_grants(self):
        original=FakeAsyncClient.post
        async def post(client,url,**kwargs):
            if url.endswith("/v1/verify/h07-case"):
                FakeAsyncClient.calls.append({"url":url,**kwargs})
                return FakeResponse({"case_id":kwargs["json"]["case_id"],"status":"ERR","course_verdict":"ERR","case_verified":False,"reason":"classifier schema invalid"})
            return await original(client,url,**kwargs)
        with patch.object(self.server.httpx,"AsyncClient",FakeAsyncClient),patch.object(FakeAsyncClient,"post",post):
            response=self.client.post("/api/practice/P07/verify",headers=self.headers)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual([row["status"] for row in response.json()["result"]["cases"]],["ERR","미실행"])
        self.assertFalse(response.json()["task_completed"])
        self.assertEqual(len([call for call in FakeAsyncClient.calls if call["url"].endswith("/v1/run-case")]),1)
        self.assertTrue(any(call["url"].endswith("/close") and "/cases/" not in call["url"] for call in FakeAsyncClient.calls))
        self.assertFalse(any(call["url"].endswith("/v1/verify/h07") for call in FakeAsyncClient.calls))

    def test_h07_learner_failure_and_request_error_close_issued_capabilities(self):
        for request_error in (False, True):
            with self.subTest(request_error=request_error):
                FakeAsyncClient.calls.clear()
                FakeAsyncClient.h07_run_status = 503
                FakeAsyncClient.h07_run_request_error = request_error
                with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient):
                    response = self.client.post("/api/hands-on/H07/verify", headers=self.headers)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["course_verdict"], "ERR")
                self.assertEqual([row["status"] for row in response.json()["result"]["cases"]], ["ERR", "미실행"])
                urls = [item["url"] for item in FakeAsyncClient.calls]
                self.assertTrue(any(url.endswith("/v1/h07/suites") for url in urls))
                self.assertTrue(any(url.endswith("/v1/run-case") for url in urls))
                self.assertTrue(any(url.endswith("/close") for url in urls))

    def test_h07_close_retries_409_and_reports_called_downstream_on_failure(self):
        FakeAsyncClient.h07_close_statuses = [409, 409, 409, 409, 409, 409]
        with patch.object(self.server.httpx, "AsyncClient", FakeAsyncClient), patch.object(
            self.server.asyncio, "sleep", return_value=None
        ):
            response = self.client.post("/api/hands-on/H07/verify", headers=self.headers)
        self.assertEqual(response.status_code, 502)
        self.assertTrue(response.json()["detail"]["downstream_called"])
        close_calls = [item for item in FakeAsyncClient.calls if item["url"].endswith("/close") and "/cases/" not in item["url"]]
        self.assertEqual(len(close_calls), 6)
        self.assertFalse(any(item["url"].endswith("/v1/verify/h07") for item in FakeAsyncClient.calls))

    def test_h22_suite_is_server_owned_and_uses_verifier(self):
        self.assertEqual(self.client.post('/api/hands-on/H22/verify',json={'course_verdict':'PASS'},headers=self.headers).status_code,422)
        with patch.object(self.server.httpx,'AsyncClient',SequentialFailureClient):
            response=self.client.post('/api/hands-on/H22/verify',headers=self.headers)
        self.assertEqual(response.status_code,200)
        result=response.json();self.assertEqual(result['activity_id'],'H22')
        self.assertEqual(result['course_verdict'],'ERR');self.assertFalse(result['task_completed'])
        run,verify=FakeAsyncClient.calls
        self.assertTrue(run['url'].endswith('/v1/run-case'))
        self.assertTrue(verify['url'].endswith('/v1/verify/h22-case'))
        self.assertEqual(run['json'],verify['json'])
        self.assertEqual(set(run['json']),{'suite_id','started_at','case_id'})
        self.assertEqual(run['json']['case_id'],'normal')
        self.assertEqual([c['status'] for c in result['result']['cases']],['ERR']+['미실행']*6)

    def test_h21_suite_is_server_owned_and_uses_verifier(self):
        self.assertEqual(self.client.post('/api/hands-on/H21/verify',json={'course_verdict':'PASS'},headers=self.headers).status_code,422)
        with patch.object(self.server.httpx,'AsyncClient',SequentialFailureClient):
            response=self.client.post('/api/hands-on/H21/verify',headers=self.headers)
        self.assertEqual(response.status_code,200)
        result=response.json();self.assertEqual(result['activity_id'],'H21')
        self.assertEqual(result['course_verdict'],'ERR');self.assertFalse(result['task_completed'])
        run,verify=FakeAsyncClient.calls
        self.assertTrue(run['url'].endswith('/v1/run-case'))
        self.assertTrue(verify['url'].endswith('/v1/verify/h21-case'))
        self.assertEqual(run['json'],verify['json'])
        self.assertEqual(set(run['json']),{'suite_id','started_at','case_id'})
        self.assertEqual(run['json']['case_id'],'normal')
        self.assertEqual([c['status'] for c in result['result']['cases']],['ERR']+['미실행']*8)

    def test_p17_uses_dedicated_runtime_and_has_no_toggle_answer(self):
        self.assertEqual(self.client.post('/api/hands-on/H17/verify',headers=self.headers,json={'task_completed':True}).status_code,422)
        with patch.object(self.server.httpx,'AsyncClient',SequentialFailureClient):
            response=self.client.post('/api/hands-on/H17/verify',headers=self.headers)
        self.assertEqual(response.status_code,200)
        run,verify=FakeAsyncClient.calls
        self.assertEqual(run['url'],self.server.H17_URL+'/v1/run-case/H17')
        self.assertEqual(run['headers'],{'Authorization':'Bearer unit-control-h17'})
        self.assertEqual(verify['url'],self.server.VERIFIER_URL+'/v1/verify/h17-case')
        self.assertEqual(run['json'],verify['json'])
        self.assertEqual([c['status'] for c in response.json()['result']['cases']],['ERR','미실행','미실행'])
        page=self.client.get('/').text
        self.assertNotIn('EXPORT_TO_ALLOY',page)
        self.assertIn('미션 채점',page)
        self.assertIn('guided-h17-telemetry',page)
        self.assertIn('aria-describedby="h17-help"',page)

    def test_p19_uses_dedicated_runtime_and_server_owned_verification(self):
        self.assertEqual(self.client.post('/api/hands-on/H19/verify',headers=self.headers,json={'suite_id':'browser-selected'}).status_code,422)
        with patch.object(self.server.httpx,'AsyncClient',SequentialFailureClient):
            response=self.client.post('/api/hands-on/H19/verify',headers=self.headers)
        self.assertEqual(response.status_code,200)
        prepare,run,verify=FakeAsyncClient.calls
        self.assertEqual(prepare['url'],self.server.H19_URL+'/v1/prepare/H19')
        self.assertEqual(run['url'],self.server.H19_URL+'/v1/run-case/H19')
        self.assertEqual(verify['url'],self.server.VERIFIER_URL+'/v1/verify/h19-case')
        self.assertEqual(run['headers'],{'Authorization':'Bearer unit-control-h19'})
        self.assertNotEqual(self.server.H19_URL,self.server.OBSERVABILITY_URL)
        self.assertEqual(run['json'],verify['json'])
        self.assertEqual(set(prepare['json']),{'suite_id','started_at'})
        self.assertEqual(run['json']['case_id'],'0-collected')
        self.assertFalse(response.json()['task_completed'])
        self.assertEqual([c['status'] for c in response.json()['result']['cases']],['ERR']+['미실행']*9)

    def test_unknown_host_is_rejected(self):
        response = self.client.get("/", headers={"Host": "attacker.example"})
        self.assertEqual(response.status_code, 421)

    def test_p20_dedicated_runtime_and_problem_without_solution(self):
        with patch.object(self.server,'H20_TOKEN','p20-control'),patch.object(self.server.httpx,'AsyncClient',SequentialFailureClient):
            self.assertEqual(self.client.post('/api/hands-on/H20/verify',headers=self.headers,json={'task_completed':True}).status_code,422)
            self.assertEqual(FakeAsyncClient.calls,[])
            response=self.client.post('/api/hands-on/H20/verify',headers=self.headers)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['course_verdict'],'ERR')
        self.assertFalse(response.json()['task_completed'])
        self.assertEqual(len(FakeAsyncClient.calls),1)
        self.assertEqual(FakeAsyncClient.calls[0]['url'],self.server.VERIFIER_URL+'/v1/verify/h20-preflight')
        self.assertEqual(set(FakeAsyncClient.calls[0]['json']),{'suite_id','started_at'})
        self.assertEqual([c['status'] for c in response.json()['result']['cases']],['ERR','미실행'])
        page=self.client.get('/').text
        self.assertIn('미션 채점',page);self.assertIn('aria-describedby="h20-help"',page)
        self.assertNotIn('guided_h20_risk_active',page);self.assertNotIn('dashboard-query.txt',page)
        self.assertIn('h20-alert-dashboard/rules.yaml',page)

    def test_p20_missing_connection_does_not_call_shared_observability(self):
        with patch.object(self.server,'H20_TOKEN',''),patch.object(self.server.httpx,'AsyncClient',FakeAsyncClient):
            response=self.client.post('/api/hands-on/H20/verify',headers=self.headers)
        self.assertEqual(response.status_code,200)
        self.assertFalse(response.json()['task_completed'])
        self.assertEqual(response.json()['course_verdict'],'ERR')
        self.assertEqual(FakeAsyncClient.calls,[])
        self.assertEqual(self.client.get('/readyz').status_code,200)

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
                        return FakeResponse({'suite_id':json['suite_id']})

                with self.subTest(stage=failure_at, failure=failure_type), patch.object(
                        self.server.httpx, 'AsyncClient', BrokenClient):
                    response = self.client.post('/api/hands-on/H19/verify', headers=self.headers)
                    self.assertEqual(response.status_code, 200)
                    detail = response.json()
                    self.assertEqual(detail['activity_id'], 'P19')
                    self.assertFalse(detail['task_completed'])
                    self.assertEqual(detail['course_verdict'], 'ERR')
                    self.assertEqual([c['status'] for c in detail['result']['cases']],['ERR']+['미실행']*9)
                    self.assertNotIn('downstream_called', detail)
                    self.assertEqual(len(FakeAsyncClient.calls), 1 if failure_at == 'learner_execution' else 3)
                    self.assertEqual(self.client.get('/readyz').status_code, 200)

    def test_session_store_evicts_idle_sessions_at_the_limit(self):
        with patch.object(self.server, "MAX_SESSIONS", 2):
            TestClient(self.server.app).get("/")
            TestClient(self.server.app).get("/")
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
            self.assertIn(f'id="{tooltip_id}" class="action-tooltip" role="note"', html)
        self.assertIn("AWS 자격 증명과 모델 연결", html)
        self.assertIn("S3 Vector Index", html)
        self.assertIn("복구 코드 요청을 거부하는 Bot 응답", html)
        self.assertNotIn('"복구 코드는 공개할 수 없습니다."', html)
        self.assertIn("NeMo Topical 평가", html)
        self.assertIn("판정 응답은 차단 시", html)
        self.assertIn("다른 공격 문장까지 모두 막는다는 뜻은 아닙니다", html)
        self.assertIn("실제로 받은 digest", html)
        self.assertIn("출력 상한과 예산 처리 코드는", html)
        javascript = (CONTROL / "guided-control-center/app.js").read_text(encoding="utf-8")
        self.assertIn("textContent", javascript)
        self.assertNotIn("innerHTML", javascript)
        self.assertIn('matchMedia("(prefers-color-scheme: dark)")', javascript)
        self.assertIn('localStorage.setItem("guided-theme-mode", mode)', javascript)
        self.assertIn('/api/practice/P01/chat', javascript)
        self.assertNotIn('class="help-trigger"', html)
        self.assertIn('<title>클씨랩 LLM 보안 실습실</title>', html)
        self.assertNotIn("TENANT 03", html)
        self.assertIn('event.key === "Escape"', javascript)
        stylesheet = (CONTROL / "guided-control-center/app.css").read_text(encoding="utf-8")
        self.assertIn("@media (max-width: 760px)", stylesheet)
        self.assertIn("color-scheme: light dark", stylesheet)
        self.assertIn(':root[data-theme="dark"]', stylesheet)
        self.assertIn("@media (prefers-color-scheme: dark)", stylesheet)
        self.assertIn("prefers-reduced-motion", stylesheet)
        self.assertIn(".action-help-summary", stylesheet)
        self.assertIn(".action-tooltip, .action-tip { display: block; position: static;", stylesheet)

    def test_only_named_public_assets_are_served_not_source_or_course_files(self):
        paths = ("/server.py", "/p01.json", "/Containerfile", "/requirements.txt",
                 "/solutions/p01.py", "/index.html", "/.state/guided-course.env",
                 "/guided-labs/h01-bedrock-gateway/learner.py", "/api/solutions",
                 "/admin-answers/P01.md")
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)

    def test_admin_url_enables_answers_without_exposing_them_to_normal_sessions(self):
        self.assertFalse(self.bootstrap["admin_mode"])
        self.assertEqual(self.client.get("/api/admin/answers/P01").status_code, 403)

        admin = TestClient(self.server.app)
        response = admin.get("/?mode=admin")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.url.query, b"mode=admin")
        self.assertTrue(admin.get("/api/bootstrap").json()["admin_mode"])
        answer = admin.get("/api/admin/answers/P01")
        self.assertEqual(answer.status_code, 200)
        self.assertEqual(answer.json()["problem"], "P01")
        self.assertIn("P01", answer.json()["answer"])
        self.assertEqual(admin.get("/api/admin/answers/P99").status_code, 404)

        admin.get("/")
        self.assertFalse(admin.get("/api/bootstrap").json()["admin_mode"])
        self.assertEqual(admin.get("/api/admin/answers/P01").status_code, 403)

    def test_admin_mode_requires_only_the_url_mode(self):
        browser = TestClient(self.server.app)
        self.assertEqual(browser.get("/?mode=admin").status_code, 200)
        self.assertTrue(browser.get("/api/bootstrap").json()["admin_mode"])

    def test_admin_answer_renderer_uses_text_content(self):
        javascript = (CONTROL / "guided-control-center/app.js").read_text(encoding="utf-8")
        self.assertIn("function renderAdminMarkdown(container, source)", javascript)
        self.assertIn('code.textContent = codeLines.join("\\n")', javascript)
        self.assertIn("function prepareCopyableBlocks(root = document)", javascript)
        self.assertIn("function prepareAdminAnswerMarkdown(source)", javascript)
        self.assertIn('renderAdminMarkdown(output, prepareAdminAnswerMarkdown(payload.answer))', javascript)
        self.assertIn('root.querySelectorAll("pre:not([id])")', javascript)
        self.assertIn("navigator.clipboard.writeText(text)", javascript)
        self.assertIn('button.textContent = copied ? "복사됨" : "복사 실패"', javascript)
        self.assertIn("prepareCopyableBlocks(output)", javascript)
        self.assertNotIn("innerHTML", javascript[javascript.index("function appendAdminInline"):javascript.index("async function showAdminAnswer")])
        self.assertNotIn("P03은 P02·P11과 별도의 문서와 자원을 사용합니다.", self.home.text)

    def test_recheck_history_is_grouped_in_one_sidebar_line(self):
        javascript = (CONTROL / "guided-control-center/app.js").read_text(encoding="utf-8")
        self.assertIn('`↻ 재검증 필요 ${problems.length}개 · ${problems.join(", ")}`', javascript)
        self.assertIn('row.title = [...new Set(recheckPractices.values())].join(" · ")', javascript)
        self.assertNotIn('`${problem} ↻ 재검증 필요 · ${reason}`', javascript)

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
            if text in ("mkdir -p ~/work/control-center-tutorial\nvi ~/work/control-center-tutorial/request.json", "cat ~/work/control-center-tutorial/request.json", "제출 명령을 준비하고 있습니다."):
                continue
            self.assertTrue(text.startswith("docker compose ") or text.startswith("cd ~/owasp-llm-lab-setup-guide") or text.startswith("vi ~/owasp-llm-lab-setup-guide/llm-security-control-plane/guided-labs/"), text[:120])
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
            'return "block" if "H16-OVERRIDE"',
            'if model not in configured["models"]:', "nonce = verify_approval(",
        )
        for fragment in forbidden:
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, html_module.unescape(assets))

    def test_p18_problem_contains_contract_but_not_completed_queries(self):
        html = (CONTROL / "guided-control-center/index.html").read_text(encoding="utf-8")
        problem = html.split('<div id="h18-work"', 1)[1].split('<div id="h19-work"', 1)[0]
        for required in ('미션 채점', 'guided-h18-queries', 'queries.yaml',
                         'request_id', 'Counter', '--no-deps', 'aria-describedby="h18-help"'):
            self.assertIn(required, problem)
        for solution in ('logql:', 'promql:', 'sum(', 'max by ('):
            self.assertNotIn(solution, problem)
        self.assertNotIn('build guided-observability', problem)

    def test_p19_problem_has_function_contract_not_answer_constant(self):
        html = (CONTROL / "guided-control-center/index.html").read_text(encoding="utf-8")
        problem = html.split('<div id="h19-work"', 1)[1].split('<div id="h20-work"', 1)[0]
        self.assertNotIn('JOIN_KEY', problem)
        for required in ('미션 채점', 'analyze_incident', 'downstream_calls', 'ValueError',
                         'build guided-h19-investigation', '--no-deps', '교육용 공지 저장소',
                         'aria-describedby="h19-help"', 'role="note"'):
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
        # Check the Starter that the next image build will publish.
        learner_source = (
            CONTROL / "guided-labs/h01-bedrock-gateway/learner.py"
        ).read_text(encoding="utf-8")
        self.assertIn("raise NotImplementedError", learner_source)
        self.assertNotIn("min(", learner_source)

        compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
        learner = compose["services"]["guided-h01-gateway"]
        baseline = compose["services"]["guided-bedrock-gateway"]
        self.assertNotEqual(learner["image"], baseline["image"])
        self.assertNotEqual(learner["container_name"], baseline["container_name"])
        self.assertIn("/tmp/.aws:ro", str(learner["volumes"]))
        self.assertNotIn("guided-h01-gateway", str(baseline))

    def test_manifest_has_13_tabs_and_23_unique_activities(self):
        manifest = yaml.safe_load(
            (CONTROL / "guided-labs/manifest.yaml").read_text(encoding="utf-8")
        )
        hands_on = [str(item) for tab in manifest["tabs"] for item in tab["hands_on"]]
        self.assertEqual(len(manifest["tabs"]), 13)
        self.assertEqual(len(hands_on), 23)
        self.assertEqual(len(set(hands_on)), 23)
        self.assertEqual(manifest["workspace"], "practice")
        self.assertEqual(manifest["execution_ids"],
                         {f"P{i:02d}": f"H{i:02d}" for i in range(1, 24)})
        self.assertEqual(hands_on[0], "H01")
        self.assertTrue(all("practice" not in tab for tab in manifest["tabs"]))
        self.assertTrue(all("practice_status" not in tab for tab in manifest["tabs"]))
        self.assertEqual(manifest["tabs"][0]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][1]["hands_on_status"], "implemented")
        self.assertEqual(manifest["tabs"][1]["implemented_hands_on"], ["H23", "H02", "H03"])
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

    def test_experience_runs_native_function_without_verdict_or_completion(self):
        from unittest.mock import AsyncMock
        class NativeClient(FakeAsyncClient):
            def stream(self,method,url,*,json,headers):
                from contextlib import asynccontextmanager
                @asynccontextmanager
                async def receive():
                    response=FakeResponse({**json,"run_state":"finished"})
                    async def chunks():yield __import__('json').dumps(response.json()).encode()
                    response.aiter_bytes=chunks
                    self.calls.append({"url":url,"json":json,"headers":headers})
                    yield response
                return receive()
            async def post(self, url, *, json=None, headers):
                if url.endswith("/v1/preview"):
                    self.calls.append({"url":url,"json":json,"headers":headers})
                    return FakeResponse({"graded":False,"reply":"native reply"})
                if url.endswith("/v1/run") or "/v1/run/H" in url:
                    self.calls.append({"url": url, "json": json, "headers": headers})
                    return FakeResponse(dict(json))
                return await super().post(url, json=json, headers=headers)
        before = self.client.get("/api/progress").json()
        for problem,config in self.server.load_experience_catalog().items():
            with self.subTest(problem=problem):
                body={"case_id":config["options"][0]["id"]} if config["mode"]=="scenario" else {"message":"native prompt"} if config["mode"]=="message" else {"operation":"lookup","message":"notice"} if config["mode"]=="operation" else None
                if config.get("editable"):body["message"]="직접 입력한 문장입니다."
                FakeAsyncClient.calls.clear()
                with patch.object(self.server, "H20_TOKEN", "unit-h20"), patch.object(self.server.httpx, "AsyncClient", NativeClient), patch.object(self.server, "exploration_result", AsyncMock(return_value={"graded": False, "result": {"native": True}})):
                    response = self.client.post("/api/experience/" + problem,json=body,headers=self.headers) if body else self.client.post("/api/experience/" + problem,headers=self.headers)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertFalse(response.json()["graded"])
                self.assertFalse(any("/v1/verify/" in call["url"] for call in FakeAsyncClient.calls))
                self.assertFalse(self.server.EXPLORATION.get())
                self.assertIsNone(self.server.PREVIEW_CASE.get())
                self.assertIsNone(self.server.PREVIEW_MESSAGE.get())
                self.assertEqual(self.client.get("/api/progress").json(), before)
                if problem in {"P05","P09","P11","P16","P21","P22"}:
                    self.assertEqual(len(FakeAsyncClient.calls),1)
                    self.assertTrue(FakeAsyncClient.calls[0]["url"].endswith('/v1/preview'))
                    expected={"case_id":body["case_id"],"query":body["message"]} if problem=="P11" else body
                    self.assertEqual(FakeAsyncClient.calls[0]['json'],expected)
                elif problem in {'P06','P07','P08','P10'}:
                    execution=next(call for call in FakeAsyncClient.calls if call['url'].endswith('/v1/run'))
                    self.assertEqual(execution['headers']['X-Preview-Case'],body['case_id'])
                    if config.get('editable'):
                        decoded=__import__('base64').urlsafe_b64decode(execution['headers']['X-Preview-Message']).decode()
                        self.assertEqual(decoded,body['message'])

    def test_experience_requires_csrf_and_dedicated_routes(self):
        self.assertEqual(TestClient(self.server.app).post("/api/experience/P06").status_code,401)
        self.assertEqual(self.client.post("/api/experience/P06").status_code,403)
        self.assertEqual(self.client.post("/api/experience/P06",json={"security_verdict":"PASS"},headers=self.headers).status_code,422)
        for problem in ("P03","P04"):
            self.assertEqual(self.client.post("/api/experience/"+problem,headers=self.headers).status_code,404)

    def test_document_upload_is_csrf_protected_and_rejects_client_identity(self):
        body = {"title":"내 문서", "body":"사용자가 입력한 문서 내용입니다."}
        self.assertEqual(TestClient(self.server.app).post("/api/documents/upload",json=body).status_code,401)
        self.assertEqual(self.client.post("/api/documents/upload",json=body).status_code,403)
        self.assertEqual(self.client.post("/api/documents/upload",json={**body,"document_id":"spoof"},headers=self.headers).status_code,422)
        self.server.RESOURCE_ACTIONS.add("P02")
        try:
            self.assertEqual(self.client.post("/api/documents/upload",json=body,headers=self.headers).status_code,409)
        finally:
            self.server.RESOURCE_ACTIONS.discard("P02")

    def test_pipeline_experience_stops_before_verifier_and_preserves_history(self):
        from unittest.mock import AsyncMock
        async def native(client, url, token, suite_id, timeout):
            return {"suite_id": suite_id, "run_state": "finished", "cases": [{"reply": "native"}]}
        before = self.client.get("/api/progress").json()
        with patch.object(self.server, "p12_post_json", AsyncMock(side_effect=native)) as run, patch.object(self.server, "exploration_result", AsyncMock(return_value={"graded": False, "result": {"cases": []}})):
            response = self.client.post("/api/experience/P12", json={"case_id":self.server.load_experience_catalog()["P12"]["options"][0]["id"]}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        run.assert_awaited_once()
        self.assertNotIn("/verify/", run.await_args.args[1])
        self.assertEqual(self.client.get("/api/progress").json(), before)


if __name__ == "__main__":
    unittest.main()
