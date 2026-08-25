"""사용자 요청의 인증·인가와 최종 응답을 집행하는 Application Gateway.

처음에는 ``ChatRequest``에서 사용자가 보낼 수 있는 필드를 확인하고, 이어서
``/api/chat``에서 인증 → RAG 등급 인가 → NeMo Hub 호출 → 응답 계약 검증 순서로
읽는다. 사용자가 보낸 Tenant나 Role을 신뢰하지 않고 Bearer Token에 서버가
연결한 Principal만 사용한다. NeMo가 검사 결과를 반환해도 Browser에 무엇을
보낼지 최종 결정하는 계층은 이 Application이다.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import uuid
from pathlib import Path
from typing import Optional

import httpx
from fastapi import Cookie, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from auth import AuthError, AuthService, InvalidCredentials, TokenReplay
from policy import (
    AuthenticationError,
    AuthorizationError,
    authenticate,
    authorize_retrieval,
    public_policy,
)
from telemetry import configure_telemetry, current_trace_id


NEMO_HUB_URL = os.getenv("NEMO_HUB_URL", "http://10.0.2.2:18094").rstrip("/")
MODEL_GATEWAY_URL = os.getenv("MODEL_GATEWAY_URL", "http://10.0.2.2:18096").rstrip("/")
SECURITY_MONITOR_URL = os.getenv("SECURITY_MONITOR_URL", "").rstrip("/")
TELEMETRY_INGEST_TOKEN = os.getenv("TELEMETRY_INGEST_TOKEN", "")
RELEASE_VERSION = os.getenv("RELEASE_VERSION", "1.0.0")
APPLICATION_INTERNAL_TOKEN = os.environ["APPLICATION_INTERNAL_TOKEN"]
BEDROCK_GATEWAY_TOKEN = os.environ["BEDROCK_GATEWAY_TOKEN"]
AUTH_USERS_PATH = os.getenv("AUTH_USERS_PATH", "/app/policies/application-users.yaml")
AUTH_STATE_DIR = os.getenv("AUTH_STATE_DIR", "/app/state")
AUTH_ISSUER = os.getenv("AUTH_ISSUER", "http://127.0.0.1:18095")
AUTH_AUDIENCE = os.getenv("AUTH_AUDIENCE", "llm-security-application")
AUTH_EVENT_SINK = {
    item.strip() for item in os.getenv("AUTH_EVENT_SINK", "stdout").split(",") if item.strip()
}
AUTH_ALLOWED_ORIGINS = {
    item.strip()
    for item in os.getenv(
        "AUTH_ALLOWED_ORIGINS", "http://127.0.0.1:18095,http://localhost:18095"
    ).split(",")
    if item.strip()
}
AUTH_SECURE_COOKIE = os.getenv("AUTH_SECURE_COOKIE", "true").lower() == "true"
AUTH_ADMIN_TOKEN = os.environ["AUTH_ADMIN_TOKEN"]
LEGACY_STATIC_TOKEN_MODE = os.getenv("LEGACY_STATIC_TOKEN_MODE", "false").lower() == "true"
if not APPLICATION_INTERNAL_TOKEN:
    raise RuntimeError("APPLICATION_INTERNAL_TOKEN is required")

auth_service = AuthService(
    users_path=AUTH_USERS_PATH,
    state_dir=AUTH_STATE_DIR,
    issuer=AUTH_ISSUER,
    audience=AUTH_AUDIENCE,
)

app = FastAPI(title="LLM security application gateway", docs_url=None, redoc_url=None)
configure_telemetry(app, "llm-security-application-gateway")


class ChatRequest(BaseModel):
    # extra="forbid"는 공격자가 정의되지 않은 권한·Tenant 필드를 끼워 넣지 못하게 한다.
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=20000)
    classification: str = Field(default="none", pattern="^(none|public|internal|restricted)$")
    purpose: str = Field(default="public_information", min_length=1, max_length=100)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


def emit_metadata(event: dict) -> None:
    print(json.dumps(event, ensure_ascii=False, separators=(",", ":")), flush=True)


def token_fingerprint(authorization: Optional[str]) -> Optional[str]:
    token = (authorization or "").partition(" ")[2]
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16] if token else None


async def emit_auth_event(event: dict) -> None:
    payload = {
        "event": "application_authentication",
        "engine": "application-auth",
        "direction": "authentication",
        **event,
    }
    if "stdout" in AUTH_EVENT_SINK:
        emit_metadata(payload)
    if (
        "monitor" not in AUTH_EVENT_SINK
        or not SECURITY_MONITOR_URL
        or not TELEMETRY_INGEST_TOKEN
    ):
        return
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.post(
                f"{SECURITY_MONITOR_URL}/api/events/guardrail",
                headers={"X-Telemetry-Token": TELEMETRY_INGEST_TOKEN},
                json=payload,
            )
            response.raise_for_status()
    except httpx.HTTPError:
        emit_metadata({"event": "auth_event_delivery_failed", "request_id": payload.get("request_id")})


def require_browser_origin(origin: Optional[str]) -> None:
    if origin not in AUTH_ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail="trusted Origin required")


def set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key="__Host-lab_refresh",
        value=token,
        max_age=auth_service.refresh_ttl,
        httponly=True,
        secure=AUTH_SECURE_COOKIE,
        samesite="strict",
        path="/",
    )


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


@app.get("/.well-known/jwks.json")
async def jwks() -> dict:
    return auth_service.jwks()


@app.post("/.well-known/login")
async def login(credentials: LoginRequest, request: Request) -> Response:
    request_id = str(uuid.uuid4())
    try:
        pair = auth_service.authenticate_password(credentials.username, credentials.password)
    except InvalidCredentials as exc:
        await emit_auth_event({
            "request_id": request_id,
            "decision": "block",
            "blocking_reason": str(exc),
            "subject": credentials.username,
            "client_ip": request.client.host if request.client else None,
        })
        raise HTTPException(status_code=401, detail="invalid username or password") from exc
    await emit_auth_event({
        "request_id": request_id,
        "decision": "allow",
        "subject": pair["subject"],
        "jti": pair["access_jti"],
        "client_ip": request.client.host if request.client else None,
    })
    response = JSONResponse({
        "access_token": pair["access_token"],
        "token_type": pair["token_type"],
        "expires_in": pair["expires_in"],
        "subject": pair["subject"],
    })
    set_refresh_cookie(response, pair["refresh_token"])
    return response


@app.post("/api/auth/refresh")
async def refresh(
    request: Request,
    origin: Optional[str] = Header(default=None),
    refresh_token: Optional[str] = Cookie(default=None, alias="__Host-lab_refresh"),
) -> Response:
    require_browser_origin(origin)
    request_id = str(uuid.uuid4())
    if not refresh_token:
        raise HTTPException(status_code=401, detail="refresh token required")
    try:
        pair = auth_service.refresh(refresh_token)
    except TokenReplay as exc:
        await emit_auth_event({
            "request_id": request_id,
            "decision": "block",
            "blocking_reason": str(exc),
            "client_ip": request.client.host if request.client else None,
        })
        raise HTTPException(status_code=401, detail="refresh token reuse detected") from exc
    except AuthError as exc:
        await emit_auth_event({
            "request_id": request_id,
            "decision": "block",
            "blocking_reason": str(exc),
            "client_ip": request.client.host if request.client else None,
        })
        raise HTTPException(status_code=401, detail="invalid refresh token") from exc
    await emit_auth_event({
        "request_id": request_id,
        "decision": "allow",
        "subject": pair["subject"],
        "jti": pair["access_jti"],
        "auth_action": "refresh",
        "client_ip": request.client.host if request.client else None,
    })
    response = JSONResponse({
        "access_token": pair["access_token"],
        "token_type": pair["token_type"],
        "expires_in": pair["expires_in"],
        "subject": pair["subject"],
    })
    set_refresh_cookie(response, pair["refresh_token"])
    return response


@app.post("/api/auth/logout", status_code=204)
async def logout(
    request: Request,
    origin: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    refresh_token: Optional[str] = Cookie(default=None, alias="__Host-lab_refresh"),
) -> Response:
    require_browser_origin(origin)
    subject = None
    for token, token_type in (
        (refresh_token, "refresh"),
        ((authorization or "").partition(" ")[2], "access"),
    ):
        if token:
            try:
                claims = auth_service.revoke(token, token_type)
                subject = subject or claims["sub"]
            except AuthError:
                pass
    await emit_auth_event({
        "request_id": str(uuid.uuid4()),
        "decision": "allow",
        "subject": subject,
        "auth_action": "logout",
        "client_ip": request.client.host if request.client else None,
    })
    response = Response(status_code=204)
    response.delete_cookie("__Host-lab_refresh", path="/")
    return response


@app.post("/api/auth/keys/rotate")
async def rotate_key(x_auth_admin_token: Optional[str] = Header(default=None)) -> dict:
    if not secrets.compare_digest(x_auth_admin_token or "", AUTH_ADMIN_TOKEN):
        raise HTTPException(status_code=403, detail="auth admin token required")
    return {"kid": auth_service.rotate_key(), "jwks": auth_service.jwks()}


@app.get("/api/security/policy")
async def policy() -> dict:
    return {
        "service": "llm-security-application-gateway",
        "version": RELEASE_VERSION,
        "canonical_source": "llm-security-control-plane/policies/application-policy.yaml",
        "runtime_source": "llm-security-control-plane/application-gateway/policy.py",
        "topology": "browser>application>nemo-hub>{presidio,nova-general-safety,application-self-check,bedrock}>application",
        **public_policy(),
    }


@app.post("/api/chat")
async def chat(
    request_context: Request,
    request: ChatRequest,
    authorization: Optional[str] = Header(default=None),
) -> dict:
    started = time.perf_counter()
    request_id = str(uuid.uuid4())
    application_stages: list[dict] = []

    # 1) 인증은 모델을 호출하기 전에 Application이 결정한다.
    try:
        principal = authenticate(
            authorization,
            auth_service=auth_service,
            legacy_static_tokens=LEGACY_STATIC_TOKEN_MODE,
        )
        application_stages.append(
            {"stage": "application_authentication", "decision": "allow", "subject": principal.subject}
        )
    except AuthenticationError as exc:
        await emit_auth_event({
            "request_id": request_id,
            "decision": "block",
            "blocking_reason": str(exc),
            "token_fingerprint": token_fingerprint(authorization),
            "client_ip": request_context.client.host if request_context.client else None,
        })
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
            # 인증·인가가 끝난 뒤에만 자격 증명 격리 Gateway에 검색을 요청한다.
            async with httpx.AsyncClient(timeout=httpx.Timeout(120.0)) as client:
                response = await client.post(
                    f"{MODEL_GATEWAY_URL}/v1/retrieve",
                    headers={"Authorization": f"Bearer {BEDROCK_GATEWAY_TOKEN}"},
                    json={"query": request.message, "number_of_results": 5},
                )
                response.raise_for_status()
                hits = response.json().get("hits", [])
            application_stages.append(
                {
                    "stage": "knowledge_base_retrieval",
                    "decision": "allow",
                    "classification": request.classification,
                    "hit_count": len(hits),
                }
            )
            allowed_suffixes = tuple(retrieval.pop("allowed_source_suffixes"))
            # Knowledge Base 검색 결과도 신뢰하지 않고 정책이 허용한 S3 source만 선택한다.
            retrieval["chunks"] = [
                hit["text"]
                for hit in hits
                if isinstance(hit, dict)
                and isinstance(hit.get("source"), str)
                and hit["source"].endswith(allowed_suffixes)
                and isinstance(hit.get("text"), str)
            ]
            if not retrieval["chunks"]:
                raise AuthorizationError("no-authorized-retrieval-hit")
            application_stages.append(
                {
                    "stage": "application_rag_selection",
                    "decision": "allow",
                    "classification": request.classification,
                    "chunk_count": len(retrieval["chunks"]),
                }
            )
    except (httpx.HTTPError, ValueError) as exc:
        result = {
            "request_id": request_id,
            "reply": "retrieval infrastructure unavailable",
            "application_decision": "infra",
            "blocking_reason": f"bedrock-retrieval:{type(exc).__name__}",
            "upstream_called": False,
            "application_stages": application_stages,
        }
        emit_metadata({"event": "application_chat", **result, "reply": None})
        return result
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
