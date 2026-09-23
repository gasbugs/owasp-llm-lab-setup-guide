"""Read-only verifier for tenant 03 learner application receipts."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from mcp import Client
from pydantic import BaseModel, ConfigDict, Field


LAB_URL = os.getenv("GUIDED_LAB01_URL", "http://guided-h01-gateway:8000")
LAB02_URL = os.getenv("GUIDED_LAB02_URL", "http://guided-h02-document-app:8000")
H22_HOST_URL = os.getenv("GUIDED_H22_HOST_URL", "http://guided-h22-host:8000")
H22_MCP_URL = os.getenv(
    "GUIDED_H22_MCP_URL", "http://guided-h22-mcp-server:8000/mcp"
)
GATEWAY_URL = os.getenv(
    "GUIDED_BEDROCK_GATEWAY_URL", "http://guided-bedrock-gateway:8080"
)
CONTROL_TOKEN = os.environ["GUIDED_CONTROL_VERIFIER_TOKEN"]
LAB_TOKEN = os.environ["GUIDED_VERIFIER_LAB01_TOKEN"]
LAB02_TOKEN = os.environ["GUIDED_VERIFIER_LAB02_TOKEN"]
H22_TOKEN = os.environ["GUIDED_VERIFIER_H22_TOKEN"]
GATEWAY_TOKEN = os.environ["GUIDED_VERIFIER_GATEWAY_TOKEN"]
DATABASE_PATH = os.getenv("GUIDED_VERIFIER_DATABASE", "/state/verifier.sqlite3")
MODEL_ID = "us.amazon.nova-lite-v1:0"
EMBEDDING_MODEL_ID = "amazon.titan-embed-text-v2:0"

Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        "CREATE TABLE IF NOT EXISTS used_evidence "
        "(provider_request_id TEXT PRIMARY KEY, execution_id TEXT NOT NULL UNIQUE)"
    )


class ExpectedCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: Literal[
        "provider-preflight",
        "normal-64",
        "risk-512",
        "invalid-empty-message",
        "reject-model-override",
    ]
    scenario: Literal["preflight", "normal", "risk"]
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    requested_max_output_tokens: int = Field(ge=1, le=512)
    expected_status: Literal[200, 422]
    observed_status: int


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    suite_kind: Literal["preflight", "hands_on"]
    cases: list[ExpectedCase] = Field(min_length=1, max_length=4)


class H02ExpectedCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: Literal[
        "normal-document", "client-key-override", "invalid-empty-body"
    ]
    scenario: Literal["normal", "risk"]
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    observed_status: Literal[200, 422]


class H02VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    cases: list[H02ExpectedCase] = Field(min_length=3, max_length=3)


class H02ResourceVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str


class H22VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str


def require_control(authorization: str | None = Header(default=None)) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, CONTROL_TOKEN):
        raise HTTPException(status_code=401, detail="invalid service credential")


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone is required")
    return parsed.astimezone(timezone.utc)


def mcp_tool_payload(result) -> dict | None:
    if isinstance(result.structured_content, dict):
        return result.structured_content
    for block in result.content:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
    return None


def err_envelope(request: VerifyRequest, reason: str) -> dict:
    return {
        "lab_id": "01-nova",
        "activity_id": "H01",
        "execution_id": request.suite_id,
        "execution_kind": "learner-gateway-suite",
        "started_at": request.started_at,
        "status": "completed",
        "course_verdict": "ERR",
        "verified_by": "guided-evidence-verifier",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "stage_calls": [],
        "evidence": [],
        "reason": reason,
        "next_check": "Gateway 요청 schema, source digest와 Provider request ID를 확인합니다.",
    }


def h02_err_envelope(request: H02VerifyRequest | H02ResourceVerifyRequest, reason: str) -> dict:
    return {
        "lab_id": "02-embedding-kb",
        "activity_id": "H02",
        "execution_id": request.suite_id,
        "execution_kind": "h02-document-suite",
        "started_at": request.started_at,
        "status": "completed",
        "course_verdict": "ERR",
        "verified_by": "guided-evidence-verifier",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "stage_calls": [],
        "evidence": [],
        "reason": reason,
        "next_check": "H02 자원 상태, source digest와 Titan·S3 영수증을 확인합니다.",
    }


def fetch_h02_resources() -> dict | None:
    response = httpx.get(
        f"{GATEWAY_URL}/v1/h02/resources",
        headers={"Authorization": f"Bearer {GATEWAY_TOKEN}"},
        timeout=10.0,
    )
    if response.status_code != 200:
        return None
    state = response.json()
    required = (
        state.get("status") == "READY",
        state.get("region") == "us-east-1",
        state.get("embedding_model_id") == EMBEDDING_MODEL_ID,
        state.get("dimensions") == 1024,
        isinstance(state.get("account_id"), str),
        len(state.get("account_id", "")) == 12,
        isinstance(state.get("template_digest"), str),
        len(state.get("template_digest", "")) == 64,
        bool(state.get("knowledge_base_id")),
        bool(state.get("data_source_id")),
        state.get("source_prefix") == "h02/knowledge/",
    )
    return state if all(required) else None


def reserve_provider_evidence(provider_id: str, execution_id: str) -> bool:
    try:
        with connect() as database:
            database.execute(
                "INSERT INTO used_evidence VALUES(?,?)", (provider_id, execution_id)
            )
        return True
    except sqlite3.IntegrityError:
        with connect() as database:
            row = database.execute(
                "SELECT execution_id FROM used_evidence WHERE provider_request_id=?",
                (provider_id,),
            ).fetchone()
        return row is not None and row["execution_id"] == execution_id


app = FastAPI(title="Tenant 03 Evidence Verifier", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    with connect() as database:
        database.execute("SELECT 1").fetchone()
    return {"status": "ready", "identity": "read-only-verifier"}


@app.post("/v1/verify/lab-01")
def verify(request: VerifyRequest, _authorized: None = Depends(require_control)) -> dict:
    expected_ids = (
        {"provider-preflight"}
        if request.suite_kind == "preflight"
        else {"normal-64", "risk-512", "invalid-empty-message", "reject-model-override"}
    )
    if {item.case_id for item in request.cases} != expected_ids:
        return err_envelope(request, "the server-owned test suite is incomplete")

    try:
        build_response = httpx.get(
            f"{LAB_URL}/v1/build-info",
            headers={"Authorization": f"Bearer {LAB_TOKEN}"},
            timeout=5.0,
        )
        if build_response.status_code != 200:
            return err_envelope(request, "learner Gateway build information is missing")
        source_digest = build_response.json().get("source_digest")
        if not isinstance(source_digest, str) or len(source_digest) != 64:
            return err_envelope(request, "learner Gateway source digest is invalid")

        verified_cases = []
        evidence = []
        for expected in request.cases:
            if expected.observed_status != expected.expected_status:
                return err_envelope(request, f"{expected.case_id} returned an unexpected HTTP status")
            receipt_response = httpx.get(
                f"{LAB_URL}/v1/receipts/{expected.execution_id}",
                headers={"Authorization": f"Bearer {LAB_TOKEN}"},
                timeout=5.0,
            )
            if expected.expected_status == 422:
                if receipt_response.status_code != 404:
                    return err_envelope(request, f"{expected.case_id} reached the Provider path")
                verified_cases.append(
                    {
                        "case_id": expected.case_id,
                        "execution_id": expected.execution_id,
                        "http_status": 422,
                        "upstream_called": False,
                    }
                )
                continue
            if receipt_response.status_code != 200:
                return err_envelope(request, "learner Gateway receipt is missing")

            receipt = receipt_response.json()
            effective = receipt.get("effective_max_output_tokens")
            usage = receipt.get("usage", {})
            provider_id = receipt.get("provider_request_id")
            try:
                started_at = parse_time(expected.started_at)
                observed_at = parse_time(receipt["observed_at"])
            except (KeyError, TypeError, ValueError):
                return err_envelope(request, "evidence timestamp is invalid")
            fields_match = all(
                (
                    receipt.get("execution_id") == expected.execution_id,
                    receipt.get("scenario") == expected.scenario,
                    receipt.get("requested_max_output_tokens") == expected.requested_max_output_tokens,
                    receipt.get("source_digest") == source_digest,
                    receipt.get("model_id") == MODEL_ID,
                    receipt.get("region") == "us-east-1",
                    receipt.get("forwarded_parameters", {}).get("maxTokens") == effective,
                    receipt.get("upstream_called") is True,
                    type(effective) is int,
                    type(usage.get("outputTokens")) is int,
                    0 <= usage.get("outputTokens", -1) <= effective,
                    isinstance(provider_id, str),
                    bool(provider_id),
                    observed_at >= started_at,
                )
            )
            if not fields_match:
                return err_envelope(request, "Gateway receipt does not match the requested execution")
            if not reserve_provider_evidence(provider_id, expected.execution_id):
                return err_envelope(request, "stale Provider evidence was reused")
            item = {
                "case_id": expected.case_id,
                "execution_id": expected.execution_id,
                "http_status": 200,
                "requested_max_output_tokens": expected.requested_max_output_tokens,
                "effective_max_output_tokens": effective,
                "source_digest": source_digest,
                "provider_request_id": provider_id,
                "model_id": receipt["model_id"],
                "region": receipt["region"],
                "forwarded_parameters": receipt["forwarded_parameters"],
                "usage": usage,
                "stop_reason": receipt["stop_reason"],
                "output_text": receipt["response_text"],
                "provider_mode": receipt["provider_mode"],
                "upstream_called": True,
            }
            verified_cases.append(item)
            evidence.append(
                {
                    "source": "amazon-bedrock" if receipt["provider_mode"] == "aws" else "contract-provider",
                    "kind": expected.case_id,
                    "id": provider_id,
                    "observed_at": receipt["observed_at"],
                }
            )
    except httpx.RequestError:
        return err_envelope(request, "read-only Gateway evidence endpoint unavailable")

    by_id = {item["case_id"]: item for item in verified_cases}
    verdict = "PASS"
    reason = "Gateway와 Provider의 새 영수증을 확인했습니다."
    if request.suite_kind == "hands_on":
        normal = by_id["normal-64"]
        risk = by_id["risk-512"]
        if normal["effective_max_output_tokens"] != 64:
            verdict = "ERR"
            reason = "정상 64 Token 요청까지 바꾸어 정상 기능 유지를 확인할 수 없습니다."
        elif risk["effective_max_output_tokens"] <= 128:
            reason = "정상 요청은 유지하고 큰 요청은 제한했으며 잘못된 body와 모델 변경도 Provider 전에 거부했습니다."
        elif risk["usage"]["outputTokens"] > 128:
            verdict = "HIT"
            reason = "512 Token 요청이 제한 없이 실제 Provider 출력으로 이어졌습니다."
        else:
            verdict = "ERR"
            reason = "전달 상한은 크지만 이번 응답이 짧아 실제 영향을 확정할 수 없습니다."

    focus = next(item for item in reversed(verified_cases) if item.get("http_status") == 200)
    return {
        "lab_id": "01-nova",
        "activity_id": "H01",
        "execution_id": request.suite_id,
        "execution_kind": "learner-gateway-suite",
        "started_at": request.started_at,
        "status": "completed",
        "course_verdict": verdict,
        "verified_by": "guided-evidence-verifier",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "stage_calls": [
            {"stage": "learner_gateway", "attempted": True, "outcome": "completed", "evidence_id": source_digest},
            {"stage": "bedrock_main", "attempted": True, "outcome": "completed", "evidence_id": focus["provider_request_id"]},
        ],
        "evidence": evidence,
        "result": {**focus, "cases": verified_cases},
        "reason": reason,
        "next_check": "네 case의 HTTP 상태, upstream_called와 Provider maxTokens를 순서대로 비교합니다.",
    }


@app.post("/v1/verify/lab-02-resources")
def verify_h02_resources(
    request: H02ResourceVerifyRequest,
    _authorized: None = Depends(require_control),
) -> dict:
    try:
        state = fetch_h02_resources()
    except httpx.RequestError:
        state = None
    if state is None:
        return h02_err_envelope(request, "Knowledge Base 연결 자원을 확인할 수 없습니다.")
    return {
        "lab_id": "02-embedding-kb",
        "activity_id": "H02",
        "execution_id": request.suite_id,
        "execution_kind": "aws-resource-provisioning",
        "started_at": request.started_at,
        "status": "completed",
        "course_verdict": "PASS",
        "verified_by": "guided-evidence-verifier",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "stage_calls": [
            {
                "stage": "s3_source",
                "attempted": True,
                "outcome": "ready",
                "evidence_id": state["source_bucket"],
            },
            {
                "stage": "s3_vector_index",
                "attempted": True,
                "outcome": "ready",
                "evidence_id": state["index_arn"],
            },
            {
                "stage": "knowledge_base",
                "attempted": True,
                "outcome": "ready",
                "evidence_id": state["knowledge_base_id"],
            },
        ],
        "evidence": [
            {
                "source": "amazon-bedrock"
                if state["provider_mode"] == "aws"
                else "contract-provider",
                "kind": "knowledge-base",
                "id": state["knowledge_base_id"],
                "observed_at": state["observed_at"],
            },
            {
                "source": "amazon-bedrock"
                if state["provider_mode"] == "aws"
                else "contract-provider",
                "kind": "data-source",
                "id": state["data_source_id"],
                "observed_at": state["observed_at"],
            },
        ],
        "result": state,
        "reason": "고정 S3 원문 경로, 1024차원 Vector Index와 Knowledge Base·Data Source 연결을 확인했습니다.",
        "next_check": "수강생 앱을 Build한 뒤 정상 문서와 경로 변경 요청을 함께 검증합니다.",
    }


@app.post("/v1/verify/lab-02")
def verify_h02(
    request: H02VerifyRequest,
    _authorized: None = Depends(require_control),
) -> dict:
    expected_ids = {"normal-document", "client-key-override", "invalid-empty-body"}
    if {item.case_id for item in request.cases} != expected_ids:
        return h02_err_envelope(request, "the server-owned H02 suite is incomplete")
    try:
        state = fetch_h02_resources()
        if state is None:
            return h02_err_envelope(request, "Knowledge Base 연결 자원이 READY가 아닙니다.")
        build_response = httpx.get(
            f"{LAB02_URL}/v1/build-info",
            headers={"Authorization": f"Bearer {LAB02_TOKEN}"},
            timeout=5.0,
        )
        if build_response.status_code != 200:
            return h02_err_envelope(request, "learner H02 build information is missing")
        source_digest = build_response.json().get("source_digest")
        if not isinstance(source_digest, str) or len(source_digest) != 64:
            return h02_err_envelope(request, "learner H02 source digest is invalid")

        verified_cases = []
        evidence = []
        for expected in request.cases:
            app_response = httpx.get(
                f"{LAB02_URL}/v1/receipts/{expected.execution_id}",
                headers={"Authorization": f"Bearer {LAB02_TOKEN}"},
                timeout=5.0,
            )
            gateway_response = httpx.get(
                f"{GATEWAY_URL}/v1/h02/evidence/{expected.execution_id}",
                headers={"Authorization": f"Bearer {GATEWAY_TOKEN}"},
                timeout=10.0,
            )
            if expected.observed_status == 422:
                if app_response.status_code != 404 or gateway_response.status_code != 404:
                    return h02_err_envelope(
                        request, f"{expected.case_id} reached the AWS document path"
                    )
                verified_cases.append(
                    {
                        "case_id": expected.case_id,
                        "execution_id": expected.execution_id,
                        "http_status": 422,
                        "upstream_called": False,
                    }
                )
                continue
            if app_response.status_code != 200 or gateway_response.status_code != 200:
                return h02_err_envelope(request, f"{expected.case_id} evidence is missing")
            app_receipt = app_response.json()
            gateway_receipt = gateway_response.json()
            try:
                started_at = parse_time(expected.started_at)
                observed_at = parse_time(gateway_receipt["observed_at"])
            except (KeyError, TypeError, ValueError):
                return h02_err_envelope(request, "H02 evidence timestamp is invalid")
            expected_key = (
                f"h02/knowledge/{expected.execution_id}.md"
                if expected.case_id == "normal-document"
                else f"h02/untrusted/{expected.execution_id}.md"
            )
            fields_match = all(
                (
                    app_receipt.get("execution_id") == expected.execution_id,
                    app_receipt.get("source_digest") == source_digest,
                    app_receipt.get("gateway_evidence_id") == expected.execution_id,
                    app_receipt.get("object_key") == expected_key,
                    gateway_receipt.get("execution_id") == expected.execution_id,
                    gateway_receipt.get("scenario") == expected.scenario,
                    gateway_receipt.get("object_key") == expected_key,
                    gateway_receipt.get("model_id") == EMBEDDING_MODEL_ID,
                    gateway_receipt.get("region") == "us-east-1",
                    gateway_receipt.get("embedding_dimension") == 1024,
                    gateway_receipt.get("knowledge_base_id")
                    == state["knowledge_base_id"],
                    gateway_receipt.get("data_source_id") == state["data_source_id"],
                    gateway_receipt.get("template_digest")
                    == state["template_digest"],
                    gateway_receipt.get("object_exists") is True,
                    gateway_receipt.get("upstream_called") is True,
                    observed_at >= started_at,
                )
            )
            if not fields_match:
                return h02_err_envelope(
                    request, f"{expected.case_id} receipt does not match the execution"
                )
            provider_id = gateway_receipt.get("provider_request_id")
            if not isinstance(provider_id, str) or not provider_id:
                return h02_err_envelope(request, "Titan request ID is missing")
            if not reserve_provider_evidence(provider_id, expected.execution_id):
                return h02_err_envelope(request, "stale Titan evidence was reused")
            item = {
                "case_id": expected.case_id,
                "execution_id": expected.execution_id,
                "http_status": 200,
                "source_digest": source_digest,
                "provider_request_id": provider_id,
                "s3_request_id": gateway_receipt["s3_request_id"],
                "provider_mode": gateway_receipt["provider_mode"],
                "model_id": gateway_receipt["model_id"],
                "object_key": gateway_receipt["object_key"],
                "object_uri": gateway_receipt["object_uri"],
                "object_exists": True,
                "embedding_dimension": 1024,
                "embedding_norm": gateway_receipt["embedding_norm"],
                "knowledge_base_id": gateway_receipt["knowledge_base_id"],
                "data_source_id": gateway_receipt["data_source_id"],
                "upstream_called": True,
            }
            verified_cases.append(item)
            evidence.extend(
                [
                    {
                        "source": "amazon-bedrock"
                        if gateway_receipt["provider_mode"] == "aws"
                        else "contract-provider",
                        "kind": expected.case_id,
                        "id": provider_id,
                        "observed_at": gateway_receipt["observed_at"],
                    },
                    {
                        "source": "amazon-s3"
                        if gateway_receipt["provider_mode"] == "aws"
                        else "contract-provider",
                        "kind": "source-object",
                        "id": gateway_receipt["s3_request_id"],
                        "observed_at": gateway_receipt["observed_at"],
                    },
                ]
            )
    except httpx.RequestError:
        return h02_err_envelope(request, "H02 read-only evidence endpoint unavailable")

    by_id = {item["case_id"]: item for item in verified_cases}
    normal = by_id["normal-document"]
    risk = by_id["client-key-override"]
    verdict = "PASS" if risk["http_status"] == 422 else "HIT"
    reason = (
        "정상 문서는 고정 S3 경로에 저장하고 Titan 1024차원 변환을 유지했으며, 클라이언트 경로 변경은 AWS 호출 전에 거부했습니다."
        if verdict == "PASS"
        else "클라이언트가 지정한 경로에 실제 S3 객체가 생기고 Titan 호출까지 실행됐습니다."
    )
    return {
        "lab_id": "02-embedding-kb",
        "activity_id": "H02",
        "execution_id": request.suite_id,
        "execution_kind": "learner-document-suite",
        "started_at": request.started_at,
        "status": "completed",
        "course_verdict": verdict,
        "verified_by": "guided-evidence-verifier",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "stage_calls": [
            {
                "stage": "learner_document_app",
                "attempted": True,
                "outcome": "completed",
                "evidence_id": source_digest,
            },
            {
                "stage": "bedrock_titan",
                "attempted": True,
                "outcome": "completed",
                "evidence_id": normal["provider_request_id"],
            },
            {
                "stage": "s3_source",
                "attempted": True,
                "outcome": "stored",
                "evidence_id": normal["s3_request_id"],
            },
            {
                "stage": "knowledge_base",
                "attempted": True,
                "outcome": "connected",
                "evidence_id": normal["knowledge_base_id"],
            },
        ],
        "evidence": evidence,
        "result": {**normal, "cases": verified_cases},
        "reason": reason,
        "next_check": "세 case의 HTTP 상태, object_key, 1024차원과 AWS 미호출 여부를 비교합니다.",
    }


@app.post("/v1/verify/lab-22")
async def verify_h22(
    request: H22VerifyRequest,
    _authorized: None = Depends(require_control),
) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0) as http_client:
            host_response = await http_client.get(
                f"{H22_HOST_URL}/v1/receipts/{request.suite_id}",
                headers={"Authorization": f"Bearer {H22_TOKEN}"},
            )
        if host_response.status_code != 200:
            raise ValueError("MCP Host receipt is missing")
        receipt = host_response.json()
        async with Client(H22_MCP_URL, mode="2026-07-28") as client:
            tools_result = await client.list_tools()
            build_result = await client.call_tool("server_build_info", {})
            effects_result = await client.call_tool(
                "audit_effects", {"suite_id": request.suite_id}
            )
            verifier_protocol = client.protocol_version
    except Exception:
        return {
            "lab_id": "13-gateway-agent",
            "activity_id": "H22",
            "execution_id": request.suite_id,
            "execution_kind": "mcp-exact-call-suite",
            "started_at": request.started_at,
            "status": "completed",
            "course_verdict": "ERR",
            "verified_by": "guided-evidence-verifier",
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "stage_calls": [],
            "evidence": [],
            "reason": "MCP Host 영수증 또는 Server 부작용을 다시 조회하지 못했습니다.",
            "next_check": "H22 Host·MCP Server 상태와 protocol version을 확인합니다.",
        }

    build = mcp_tool_payload(build_result) or {}
    effects = mcp_tool_payload(effects_result) or {}
    effect_calls = effects.get("calls", [])
    verifier_inventory = sorted(tool.name for tool in tools_result.tools)
    verifier_inventory_digest = hashlib.sha256(
        "\n".join(verifier_inventory).encode()
    ).hexdigest()
    required_tools = {
        "lookup_notice",
        "publish_notice",
        "audit_effects",
        "server_build_info",
    }
    fields_match = all(
        (
            receipt.get("suite_id") == request.suite_id,
            receipt.get("started_at") == request.started_at,
            receipt.get("protocol_version") == "2026-07-28",
            verifier_protocol == "2026-07-28",
            receipt.get("server_id") == "training-notice-mcp",
            set(receipt.get("tool_inventory", [])) == required_tools,
            verifier_inventory == receipt.get("tool_inventory"),
            receipt.get("tool_inventory_digest") == verifier_inventory_digest,
            receipt.get("source_digest") == build.get("source_digest"),
            build.get("server_id") == "training-notice-mcp",
            build.get("protocol_version") == "2026-07-28",
            effects.get("suite_id") == request.suite_id,
            effects.get("effects") == len(effect_calls),
            receipt.get("external_action_called") is False,
            effects.get("external_action_called") is False,
        )
    )
    if not fields_match:
        verdict = "ERR"
        reason = "Host 영수증과 MCP Server의 protocol·Tool·source·부작용 증거가 일치하지 않습니다."
    elif (
        not receipt.get("no_approval", {}).get("is_error")
        and isinstance(receipt.get("effect_counts"), list)
        and len(receipt["effect_counts"]) == 4
        and receipt["effect_counts"][0] > 0
        and effects.get("effects", 0) >= receipt["effect_counts"][0]
    ):
        verdict = "HIT"
        reason = "승인 없는 tools/call이 로컬 공지를 실제로 만들어 서버 인가 우회가 확인됐습니다."
    else:
        safe_path = all(
            (
                receipt.get("normal", {}).get("is_error") is False,
                receipt.get("self_approval", {}).get("denied") is True,
                receipt.get("changed_args", {}).get("is_error") is True,
                receipt.get("approved", {}).get("is_error") is False,
                receipt.get("reuse", {}).get("is_error") is True,
                receipt.get("effect_counts") == [0, 0, 1, 1],
                effects.get("effects") == 1,
                len(effect_calls) == 1,
                effect_calls[0].get("call_id") == receipt.get("approved_call_id")
                if effect_calls
                else False,
            )
        )
        verdict = "PASS" if safe_path else "ERR"
        reason = (
            "정상 조회를 유지하고 승인 없음·self-approval·인자 변경·재사용을 막았으며 정확한 승인 한 건만 실행했습니다."
            if safe_path
            else "승인 차단 또는 정상 일회 실행 가운데 하나의 증거가 부족합니다."
        )

    return {
        "lab_id": "13-gateway-agent",
        "activity_id": "H22",
        "execution_id": request.suite_id,
        "execution_kind": "mcp-exact-call-suite",
        "started_at": request.started_at,
        "status": "completed",
        "course_verdict": verdict,
        "verified_by": "guided-evidence-verifier",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "stage_calls": [
            {
                "stage": "mcp_host",
                "attempted": True,
                "outcome": "completed",
                "evidence_id": receipt.get("tool_inventory_digest"),
            },
            {
                "stage": "mcp_server",
                "attempted": True,
                "outcome": "completed",
                "evidence_id": build.get("source_digest"),
            },
            {
                "stage": "training_effect",
                "attempted": True,
                "outcome": f"effects={effects.get('effects')}",
                "evidence_id": receipt.get("approved_call_id"),
            },
        ],
        "evidence": [
            {
                "source": "mcp-server",
                "kind": "tool-inventory",
                "id": receipt.get("tool_inventory_digest"),
                "observed_at": receipt.get("observed_at"),
            },
            {
                "source": "mcp-server",
                "kind": "source-build",
                "id": build.get("source_digest"),
                "observed_at": receipt.get("observed_at"),
            },
        ],
        "result": {
            **receipt,
            "verified_effects": effects,
            "verifier_protocol_version": verifier_protocol,
        },
        "reason": reason,
        "next_check": "protocol version, Tool 목록, 승인 없는 호출과 0→0→1→1 부작용 순서를 확인합니다.",
    }
