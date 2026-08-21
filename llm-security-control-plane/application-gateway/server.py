"""Browser-facing Application Gateway for the NeMo hub-and-spoke lab."""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from policy import (
    AuthenticationError,
    AuthorizationError,
    authenticate,
    authorize_retrieval,
    public_policy,
)
from telemetry import configure_telemetry, current_trace_id


NEMO_HUB_URL = os.getenv("NEMO_HUB_URL", "http://10.0.2.2:18094").rstrip("/")
SECURITY_MONITOR_URL = os.getenv("SECURITY_MONITOR_URL", "").rstrip("/")
TELEMETRY_INGEST_TOKEN = os.getenv("TELEMETRY_INGEST_TOKEN", "")
RELEASE_VERSION = os.getenv("RELEASE_VERSION", "1.0.0")
APPLICATION_INTERNAL_TOKEN = os.getenv("APPLICATION_INTERNAL_TOKEN", "")
if not APPLICATION_INTERNAL_TOKEN:
    raise RuntimeError("APPLICATION_INTERNAL_TOKEN is required")

app = FastAPI(title="LLM security application gateway", docs_url=None, redoc_url=None)
configure_telemetry(app, "llm-security-application-gateway")


class ChatRequest(BaseModel):
    # extra="forbid"는 공격자가 정의되지 않은 권한·Tenant 필드를 끼워 넣지 못하게 한다.
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=20000)
    classification: str = Field(default="none", pattern="^(none|public|internal|restricted)$")
    purpose: str = Field(default="public_information", min_length=1, max_length=100)


def emit_metadata(event: dict) -> None:
    print(json.dumps(event, ensure_ascii=False, separators=(",", ":")), flush=True)


async def observe_guardrail(result: dict) -> None:
    """Send metadata-only stage decisions to Module 08 when it is connected."""
    if not SECURITY_MONITOR_URL or not TELEMETRY_INGEST_TOKEN:
        return
    guardrail = result.get("guardrail") or {}
    common = {
        "request_id": result.get("request_id"),
        "guard_mode": guardrail.get("mode"),
        "upstream_called": guardrail.get("upstream_called"),
        "guard_model_calls": guardrail.get("guard_model_calls", 0),
    }
    events = [{
        **common,
        "event": "control_plane_decision",
        "engine": "nemo",
        "direction": "chat",
        "decision": guardrail.get("decision", "infra"),
        "blocking_reason": guardrail.get("blocking_reason"),
        "duration_ms": guardrail.get("duration_ms", 0),
    }]
    for stage in guardrail.get("stages", []):
        engine = "presidio" if str(stage.get("engine", "")).startswith("presidio") else "nemo"
        direction = "output" if "output" in str(stage.get("stage")) else "input"
        decision = stage.get("decision", "observe")
        if decision == "allow_unredacted":
            decision = "allow"
        events.append({
            **common,
            "event": "control_plane_stage",
            "engine": engine,
            "direction": direction,
            "decision": decision,
            "duration_ms": stage.get("duration_ms", 0),
            "entity_types": stage.get("entity_types", []),
        })
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            for event in events:
                await client.post(
                    f"{SECURITY_MONITOR_URL}/api/events/guardrail",
                    headers={"X-Telemetry-Token": TELEMETRY_INGEST_TOKEN},
                    json=event,
                )
    except httpx.HTTPError:
        emit_metadata({"event": "telemetry_delivery_failed", "request_id": result.get("request_id")})


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return Path("/app/index.html").read_text(encoding="utf-8")


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "service": "llm-security-application-gateway", "version": RELEASE_VERSION}


@app.get("/api/security/policy")
async def policy() -> dict:
    return {
        "service": "llm-security-application-gateway",
        "version": RELEASE_VERSION,
        "canonical_source": "llm-security-control-plane/policies/application-policy.yaml",
        "runtime_source": "llm-security-control-plane/application-gateway/policy.py",
        "topology": "browser>application>nemo-hub>{presidio,llama-guard,self-check,ollama}>application",
        **public_policy(),
    }


@app.post("/api/chat")
async def chat(
    request: ChatRequest,
    authorization: str | None = Header(default=None),
) -> dict:
    started = time.perf_counter()
    request_id = str(uuid.uuid4())
    application_stages: list[dict] = []

    # 1) 인증은 모델을 호출하기 전에 Application이 결정한다.
    try:
        principal = authenticate(authorization)
        application_stages.append(
            {"stage": "application_authentication", "decision": "allow", "subject": principal.subject}
        )
    except AuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    # 2) 인증된 Principal의 역할·목적·데이터 등급으로 RAG 접근을 인가한다.
    # 차단 시 NeMo Hub와 Main Model은 호출되지 않는다.
    try:
        retrieval = authorize_retrieval(principal, request.classification, request.purpose)
        application_stages.append(
            {
                "stage": "application_authorization",
                "decision": "allow",
                "classification": request.classification,
                "purpose": request.purpose,
            }
        )
        if retrieval:
            application_stages.append(
                {
                    "stage": "application_rag_selection",
                    "decision": "allow",
                    "classification": request.classification,
                    "chunk_count": len(retrieval["chunks"]),
                }
            )
    except AuthorizationError as exc:
        application_stages.append(
            {
                "stage": "application_authorization",
                "decision": "block",
                "classification": request.classification,
                "purpose": request.purpose,
            }
        )
        result = {
            "request_id": request_id,
            "reply": "애플리케이션 권한 정책이 해당 RAG 접근을 차단했습니다.",
            "application_decision": "block",
            "blocking_reason": str(exc),
            "upstream_called": False,
            "application_stages": application_stages,
        }
        emit_metadata({"event": "application_chat", **result, "reply": None})
        return result

    # 3) 원본 Bearer Token 대신 검증된 Principal과 인가된 Retrieval만 Hub에 전달한다.
    payload = {
        "message": request.message,
        "request_id": request_id,
        "principal": {"subject": principal.subject, "roles": sorted(principal.roles)},
        "retrieval": retrieval,
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(300.0)) as client:
            response = await client.post(
                f"{NEMO_HUB_URL}/api/chat",
                headers={"Authorization": f"Bearer {APPLICATION_INTERNAL_TOKEN}"},
                json=payload,
            )
            response.raise_for_status()
            hub = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        result = {
            "request_id": request_id,
            "reply": "guardrail infrastructure unavailable",
            "application_decision": "infra",
            "blocking_reason": f"nemo-hub:{type(exc).__name__}",
            "upstream_called": False,
            "application_stages": application_stages,
        }
        emit_metadata({"event": "application_chat", **result, "reply": None})
        return result

    # 4) 내부 서비스 응답도 신뢰하지 않는다. request_id와 필수 계약을 검증하고
    # 계약이 깨지면 응답을 사용자에게 전달하지 않고 fail closed 한다.
    guardrail = hub.get("guardrail")
    if (
        hub.get("request_id") != request_id
        or not isinstance(hub.get("reply"), str)
        or not isinstance(guardrail, dict)
        or guardrail.get("decision") not in {"allow", "redact", "block", "infra"}
    ):
        result = {
            "request_id": request_id,
            "reply": "guardrail infrastructure unavailable",
            "application_decision": "infra",
            "blocking_reason": "nemo-hub:invalid-contract",
            "upstream_called": False,
            "application_stages": application_stages,
        }
        emit_metadata({"event": "application_chat", **result, "reply": None})
        return result

    # 5) Hub의 판정을 Application 최종 응답 경계에서 한 번 더 집행한다.
    application_stages.append(
        {
            "stage": "application_final_enforcement",
            "decision": guardrail["decision"],
        }
    )
    result = {
        "request_id": request_id,
        "trace_id": current_trace_id(),
        "reply": hub["reply"],
        "application_decision": guardrail["decision"],
        "blocking_reason": guardrail.get("blocking_reason"),
        "upstream_called": bool(guardrail.get("upstream_called")),
        "authenticated_subject": principal.subject,
        "classification": request.classification,
        "application_stages": application_stages,
        "guardrail": guardrail,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }
    emit_metadata(
        {
            "event": "application_chat",
            "request_id": request_id,
            "subject": principal.subject,
            "classification": request.classification,
            "application_decision": result["application_decision"],
            "blocking_reason": result["blocking_reason"],
            "upstream_called": result["upstream_called"],
            "duration_ms": result["duration_ms"],
        }
    )
    await observe_guardrail(result)
    return result
