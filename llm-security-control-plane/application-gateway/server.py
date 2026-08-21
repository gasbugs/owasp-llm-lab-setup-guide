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


NEMO_HUB_URL = os.getenv("NEMO_HUB_URL", "http://10.0.2.2:18094").rstrip("/")
APPLICATION_INTERNAL_TOKEN = os.getenv("APPLICATION_INTERNAL_TOKEN", "")
if not APPLICATION_INTERNAL_TOKEN:
    raise RuntimeError("APPLICATION_INTERNAL_TOKEN is required")

app = FastAPI(title="LLM security application gateway", docs_url=None, redoc_url=None)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=20000)
    classification: str = Field(default="none", pattern="^(none|public|internal|restricted)$")
    purpose: str = Field(default="public_information", min_length=1, max_length=100)


def emit_metadata(event: dict) -> None:
    print(json.dumps(event, ensure_ascii=False, separators=(",", ":")), flush=True)


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return Path("/app/index.html").read_text(encoding="utf-8")


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "service": "llm-security-application-gateway", "version": "1.0.0"}


@app.get("/api/security/policy")
async def policy() -> dict:
    return {
        "service": "llm-security-application-gateway",
        "version": "1.0.0",
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

    try:
        principal = authenticate(authorization)
        application_stages.append(
            {"stage": "application_authentication", "decision": "allow", "subject": principal.subject}
        )
    except AuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

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

    application_stages.append(
        {
            "stage": "application_final_enforcement",
            "decision": guardrail["decision"],
        }
    )
    result = {
        "request_id": request_id,
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
    return result
