"""Same-origin learning UI orchestrator for the tenant 03 vertical slice."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field


ROOT = Path(__file__).parent
APP_VERSION = os.getenv("RELEASE_VERSION", os.getenv("APP_VERSION", "dev"))
SESSION_SECRET = os.environ["GUIDED_SESSION_SECRET"].encode()
LAB_URL = os.getenv("GUIDED_LAB01_URL", "http://guided-h01-gateway:8000")
LAB02_URL = os.getenv("GUIDED_LAB02_URL", "http://guided-h02-document-app:8000")
LAB03_URL = os.getenv("GUIDED_LAB03_URL", "http://guided-h03-sync-app:8000")
LAB04_URL = os.getenv("GUIDED_LAB04_URL", "http://guided-h04-guardrail-app:8000")
LAB05_URL = os.getenv("GUIDED_LAB05_URL", "http://guided-h05-nemo-dialog:8000")
LAB06_URL = os.getenv("GUIDED_LAB06_URL", "http://guided-h06-nemo-action:8000")
LAB07_URL = os.getenv("GUIDED_LAB07_URL", "http://guided-h07-content-safety:8000")
H06_PROVIDER_URL = os.getenv(
    "GUIDED_H06_PROVIDER_URL", "http://guided-h06-action-provider:8000"
)
H22_HOST_URL = os.getenv("GUIDED_H22_HOST_URL", "http://guided-h22-host:8000")
H21_HOST_URL = os.getenv("GUIDED_H21_HOST_URL", "http://guided-h21-host:8000")
GATEWAY_URL = os.getenv(
    "GUIDED_BEDROCK_GATEWAY_URL", "http://guided-bedrock-gateway:8080"
)
VERIFIER_URL = os.getenv("GUIDED_VERIFIER_URL", "http://guided-evidence-verifier:8000")
LAB_TOKEN = os.environ["GUIDED_CONTROL_LAB01_TOKEN"]
LAB02_TOKEN = os.environ["GUIDED_CONTROL_LAB02_TOKEN"]
LAB03_TOKEN = os.environ["GUIDED_CONTROL_LAB03_TOKEN"]
LAB04_TOKEN = os.environ["GUIDED_CONTROL_LAB04_TOKEN"]
LAB05_TOKEN = os.environ["GUIDED_CONTROL_LAB05_TOKEN"]
LAB06_TOKEN = os.environ["GUIDED_CONTROL_LAB06_TOKEN"]
LAB07_TOKEN = os.environ["GUIDED_CONTROL_LAB07_TOKEN"]
H06_PROVIDER_CONTROL_TOKEN = os.environ["GUIDED_H06_PROVIDER_CONTROL_TOKEN"]
H07_GATEWAY_CONTROL_TOKEN = os.environ["GUIDED_H07_GATEWAY_CONTROL_TOKEN"]
H22_TOKEN = os.environ["GUIDED_CONTROL_H22_TOKEN"]
H21_TOKEN = os.environ["GUIDED_CONTROL_H21_TOKEN"]
H02_PROVISION_TOKEN = os.environ["GUIDED_LAB02_PROVISION_TOKEN"]
H03_PROVISION_TOKEN = os.environ["GUIDED_LAB03_PROVISION_TOKEN"]
H04_PROVISION_TOKEN = os.environ["GUIDED_LAB04_PROVISION_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_CONTROL_VERIFIER_TOKEN"]
ALLOWED_HOSTS = set(
    os.getenv(
        "GUIDED_ALLOWED_HOSTS", "127.0.0.1:18097,localhost:18097,testserver"
    ).split(",")
)
ALLOWED_ORIGINS = set(
    os.getenv(
        "GUIDED_ALLOWED_ORIGINS",
        "http://127.0.0.1:18097,http://localhost:18097,http://testserver",
    ).split(",")
)
TIMEOUT = httpx.Timeout(130.0, connect=3.0)
PROVISION_TIMEOUT = httpx.Timeout(360.0, connect=3.0)
H07_CLOSE_TIMEOUT = httpx.Timeout(3.0, connect=1.0)
MODEL_ID = "us.amazon.nova-lite-v1:0"
NEMO_BROWSER_URL = os.getenv("GUIDED_NEMO_BROWSER_URL", "http://127.0.0.1:18192")
SESSIONS: dict[str, dict] = {}
ACTIVE_SESSIONS: set[str] = set()
MAX_SESSIONS = 256


class ChatInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=4000)


def sign(session_id: str) -> str:
    signature = hmac.new(SESSION_SECRET, session_id.encode(), hashlib.sha256).hexdigest()
    return f"{session_id}.{signature}"


def session_from_cookie(cookie: str | None) -> tuple[str, dict]:
    session_id, separator, signature = (cookie or "").partition(".")
    expected = hmac.new(SESSION_SECRET, session_id.encode(), hashlib.sha256).hexdigest()
    if not separator or not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail="session is missing or invalid")
    session = SESSIONS.get(session_id)
    if session is None:
        raise HTTPException(status_code=401, detail="session has expired")
    return session_id, session


def require_session(
    guided_session: str | None = Cookie(default=None),
) -> tuple[str, dict]:
    return session_from_cookie(guided_session)


def require_csrf(
    request: Request,
    x_csrf_token: str | None = Header(default=None),
    session: tuple[str, dict] = Depends(require_session),
) -> tuple[str, dict]:
    origin = request.headers.get("origin")
    if origin not in ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail="origin is not allowed")
    if not x_csrf_token or not hmac.compare_digest(x_csrf_token, session[1]["csrf"]):
        raise HTTPException(status_code=403, detail="CSRF token is invalid")
    return session


def security_headers(response: Response) -> None:
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"


app = FastAPI(title="LLM Security Guided Control Center", docs_url=None, redoc_url=None)


@app.middleware("http")
async def boundary_middleware(request: Request, call_next):
    if request.headers.get("host", "") not in ALLOWED_HOSTS:
        response = JSONResponse(status_code=421, content={"detail": "host is not allowed"})
        security_headers(response)
        return response
    response = await call_next(request)
    security_headers(response)
    return response


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    while len(SESSIONS) >= MAX_SESSIONS:
        oldest_idle = next(
            (candidate for candidate in SESSIONS if candidate not in ACTIVE_SESSIONS),
            None,
        )
        if oldest_idle is None:
            raise HTTPException(status_code=503, detail="all guided sessions are busy")
        SESSIONS.pop(oldest_idle, None)
    session_id = secrets.token_urlsafe(24)
    SESSIONS[session_id] = {
        "csrf": secrets.token_urlsafe(24),
    }
    html = (ROOT / "index.html").read_text(encoding="utf-8").replace(
        "__APP_VERSION__", APP_VERSION
    )
    response = HTMLResponse(html)
    response.set_cookie(
        "guided_session",
        sign(session_id),
        httponly=True,
        samesite="strict",
        secure=False,
        path="/",
    )
    return response


@app.get("/app.css")
def stylesheet() -> FileResponse:
    return FileResponse(ROOT / "app.css", media_type="text/css")


@app.get("/app.js")
def javascript() -> FileResponse:
    return FileResponse(ROOT / "app.js", media_type="text/javascript")


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive", "service": "guided-control-center"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    return {"status": "ready", "provider_check": "not-run"}


@app.get("/api/bootstrap")
def bootstrap(session: tuple[str, dict] = Depends(require_session)) -> dict:
    return {
        "csrf_token": session[1]["csrf"],
        "course": {
            "tabs": 13,
            "hands_on": 22,
            "practices": 13,
            "implemented_hands_on": ["H01", "H02", "H03", "H04", "H05", "H06", "H07", "H21", "H22"],
            "implemented_practices": [],
        },
        "official_uis": [
            {
                "id": "nemo",
                "name": "NeMo Chat UI",
                "browser_url": NEMO_BROWSER_URL,
                "status": "ready",
                "boundary": "NeMo 단독 Rail 화면이며 H01 판정은 Control Center가 수행합니다.",
            },
            {
                "id": "bedrock",
                "name": "Amazon Bedrock Console",
                "browser_url": "https://console.aws.amazon.com/bedrock/home?region=us-east-1",
                "status": "external",
                "boundary": "AWS 로그인과 수강생 본인 계정 권한을 사용합니다.",
            },
        ],
        "learner_app": {
            "hands_on_id": "H01",
            "service": "guided-h01-gateway",
            "source_path": "llm-security-control-plane/guided-labs/h01-bedrock-gateway/server.py",
            "compose_path": "examples/security-monitoring/compose.guided.yaml",
        },
        "learner_apps": [
            {
                "hands_on_id": "H01",
                "service": "guided-h01-gateway",
                "source_path": "llm-security-control-plane/guided-labs/h01-bedrock-gateway/server.py",
            },
            {
                "hands_on_id": "H02",
                "service": "guided-h02-document-app",
                "source_path": "llm-security-control-plane/guided-labs/h02-document-ingestion/server.py",
            },
            {
                "hands_on_id": "H03",
                "service": "guided-h03-sync-app",
                "source_path": "llm-security-control-plane/guided-labs/h03-ingestion-search/server.py",
            },
            {
                "hands_on_id": "H04",
                "service": "guided-h04-guardrail-app",
                "source_path": "llm-security-control-plane/guided-labs/h04-bedrock-guardrail/server.py",
            },
            {
                "hands_on_id": "H05",
                "service": "guided-h05-nemo-dialog",
                "source_path": "llm-security-control-plane/guided-labs/h05-nemo-dialog/config/flows.co",
            },
            {
                "hands_on_id": "H06",
                "service": "guided-h06-nemo-action",
                "source_path": "llm-security-control-plane/guided-labs/h06-nemo-action/actions.py",
            },
            {
                "hands_on_id": "H07",
                "service": "guided-h07-content-safety",
                "source_path": "llm-security-control-plane/guided-labs/h07-content-safety/config/config.yml",
            },
            {
                "hands_on_id": "H21",
                "service": "guided-h21-host",
                "source_path": "llm-security-control-plane/guided-labs/h21-agent-policy/policy.py",
            },
            {
                "hands_on_id": "H22",
                "service": "guided-h22-mcp-server",
                "source_path": "llm-security-control-plane/guided-labs/h22-mcp-approval/server.py",
            },
        ],
    }


async def execute_suite(session_id: str, suite_kind: str) -> dict:
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    suite_id = str(uuid.uuid4())
    suite_started_at = datetime.now(timezone.utc).isoformat()
    definitions = (
        [
            {
                "case_id": "provider-preflight",
                "scenario": "preflight",
                "prompt": "Reply only OK",
                "message": "Reply only OK",
                "max_output_tokens": 2,
                "expected_status": 200,
            }
        ]
        if suite_kind == "preflight"
        else [
            {
                "case_id": "normal-64",
                "scenario": "normal",
                "message": "GUIDED-H01-NORMAL: TLS 인증서 교체 절차를 세 문장으로 요약하세요.",
                "max_output_tokens": 64,
                "expected_status": 200,
            },
            {
                "case_id": "risk-512",
                "scenario": "risk",
                "message": "GUIDED-H01-RISK: 상담 절차를 출력 한계까지 상세히 작성하세요.",
                "max_output_tokens": 512,
                "expected_status": 200,
            },
            {
                "case_id": "invalid-empty-message",
                "scenario": "normal",
                "message": "",
                "max_output_tokens": 64,
                "expected_status": 422,
            },
            {
                "case_id": "reject-model-override",
                "scenario": "normal",
                "message": "임의 모델로 바꾸어 주세요.",
                "max_output_tokens": 64,
                "model": "attacker-selected-model",
                "expected_status": 422,
            },
        ]
    )
    cases = []
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            for definition in definitions:
                execution_id = str(uuid.uuid4())
                started_at = datetime.now(timezone.utc).isoformat()
                lab_response = await client.post(
                    f"{LAB_URL}/v1/chat",
                    json={
                        "execution_id": execution_id,
                        "started_at": started_at,
                        "message": definition["message"],
                        "max_output_tokens": definition["max_output_tokens"],
                        "scenario": definition["scenario"],
                        **({"model": definition["model"]} if "model" in definition else {}),
                    },
                    headers={"Authorization": f"Bearer {LAB_TOKEN}"},
                )
                if lab_response.status_code != definition["expected_status"]:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "successful_stage": "control_center",
                            "stopped_stage": "guided_h01_gateway",
                            "downstream_called": False,
                            "course_verdict": "ERR",
                            "next_check": "guided-h01-gateway의 요청 schema와 컨테이너 상태를 확인합니다.",
                        },
                    )
                cases.append(
                    {
                        "case_id": definition["case_id"],
                        "scenario": definition["scenario"],
                        "execution_id": execution_id,
                        "started_at": started_at,
                        "requested_max_output_tokens": definition["max_output_tokens"],
                        "expected_status": definition["expected_status"],
                        "observed_status": lab_response.status_code,
                    }
                )
            verifier_response = await client.post(
                f"{VERIFIER_URL}/v1/verify/lab-01",
                json={
                    "suite_id": suite_id,
                    "started_at": suite_started_at,
                    "suite_kind": suite_kind,
                    "cases": cases,
                },
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verifier_response.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verifier_response.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/provider-preflight")
async def provider_preflight(
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    return await execute_suite(session[0], "preflight")


@app.post("/api/hands-on/H01/verify")
async def verify_learner_app(
    request: Request,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if await request.body():
        raise HTTPException(status_code=422, detail="verification inputs are server-owned")
    return await execute_suite(session[0], "hands_on")


@app.post("/api/hands-on/H01/chat")
async def chat_with_learner_app(
    chat: ChatInput,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    session_id = session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    execution_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(
                f"{LAB_URL}/v1/chat",
                json={
                    "execution_id": execution_id,
                    "started_at": started_at,
                    "message": chat.prompt,
                    "max_output_tokens": 512,
                    "scenario": "chat",
                },
                headers={"Authorization": f"Bearer {LAB_TOKEN}"},
            )
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail="guided H01 Gateway chat failed")
        result = response.json()
        return {
            "activity_id": "H01",
            "execution_kind": "exploratory_chat",
            "graded": False,
            "execution_id": execution_id,
            "started_at": started_at,
            "stage_calls": [
                {"stage": "learner_gateway", "outcome": "completed"},
                {"stage": "bedrock_main", "outcome": "completed"},
            ],
            "result": result,
        }
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H02/provision")
async def provision_h02_resources(
    request: Request,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if await request.body():
        raise HTTPException(status_code=422, detail="provisioning inputs are server-owned")
    session_id = session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    execution_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            provision_response = await client.post(
                f"{GATEWAY_URL}/v1/h02/provision",
                json={"execution_id": execution_id},
                headers={"Authorization": f"Bearer {H02_PROVISION_TOKEN}"},
            )
            if provision_response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "control_center",
                        "stopped_stage": "h02_aws_provisioning",
                        "downstream_called": True,
                        "course_verdict": "ERR",
                        "next_check": "Gateway 원시 오류와 현재 AWS 자원 상태를 확인합니다.",
                    },
                )
            verifier_response = await client.post(
                f"{VERIFIER_URL}/v1/verify/lab-02-resources",
                json={"suite_id": execution_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verifier_response.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verifier_response.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H02/verify")
async def verify_h02_document_app(
    request: Request,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if await request.body():
        raise HTTPException(status_code=422, detail="verification inputs are server-owned")
    session_id = session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    suite_id = str(uuid.uuid4())
    suite_started_at = datetime.now(timezone.utc).isoformat()
    definitions = [
        {
            "case_id": "normal-document",
            "scenario": "normal",
            "title": "모바일 송금 장애 절차",
            "body": "모바일 송금 장애는 앱 재실행과 네트워크 상태를 먼저 확인하고 공식 고객센터에서 사건 번호를 발급받습니다.",
        },
        {
            "case_id": "client-key-override",
            "scenario": "risk",
            "title": "경로 변경 시도",
            "body": "클라이언트가 서버 소유 저장 경로를 바꾸려는 H02 보안 검증 문서입니다.",
            "object_key_override": True,
        },
        {
            "case_id": "invalid-empty-body",
            "scenario": "normal",
            "title": "빈 문서",
            "body": "",
        },
    ]
    cases = []
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            for definition in definitions:
                execution_id = str(uuid.uuid4())
                started_at = datetime.now(timezone.utc).isoformat()
                payload = {
                    "execution_id": execution_id,
                    "started_at": started_at,
                    "title": definition["title"],
                    "body": definition["body"],
                    "scenario": definition["scenario"],
                }
                if definition.get("object_key_override"):
                    payload["object_key"] = f"h02/untrusted/{execution_id}.md"
                response = await client.post(
                    f"{LAB02_URL}/v1/documents",
                    json=payload,
                    headers={"Authorization": f"Bearer {LAB02_TOKEN}"},
                )
                if definition["case_id"] == "normal-document" and response.status_code != 200:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "successful_stage": "control_center",
                            "stopped_stage": "guided_h02_document_app",
                            "downstream_called": False,
                            "course_verdict": "ERR",
                            "next_check": "H02 자원 상태와 수강생 앱의 Gateway 요청을 확인합니다.",
                        },
                    )
                if definition["case_id"] == "invalid-empty-body" and response.status_code != 422:
                    raise HTTPException(
                        status_code=502,
                        detail="invalid H02 body did not stop at the HTTP schema",
                    )
                if definition["case_id"] == "client-key-override" and response.status_code not in {200, 422}:
                    raise HTTPException(
                        status_code=502,
                        detail="H02 risk case returned an unexpected HTTP status",
                    )
                cases.append(
                    {
                        "case_id": definition["case_id"],
                        "scenario": definition["scenario"],
                        "execution_id": execution_id,
                        "started_at": started_at,
                        "observed_status": response.status_code,
                    }
                )
            verifier_response = await client.post(
                f"{VERIFIER_URL}/v1/verify/lab-02",
                json={
                    "suite_id": suite_id,
                    "started_at": suite_started_at,
                    "cases": cases,
                },
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verifier_response.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verifier_response.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H03/provision")
async def provision_h03_baseline(
    request: Request,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if await request.body():
        raise HTTPException(status_code=422, detail="provisioning inputs are server-owned")
    session_id = session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    execution_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            response = await client.post(
                f"{GATEWAY_URL}/v1/h03/provision",
                json={"execution_id": execution_id},
                headers={"Authorization": f"Bearer {H03_PROVISION_TOKEN}"},
            )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "control_center",
                        "stopped_stage": "h03_baseline_provisioning",
                        "downstream_called": True,
                        "course_verdict": "ERR",
                        "next_check": "H03 Gateway 원시 오류와 전용 AWS 자원 상태를 확인합니다.",
                    },
                )
            verified = await client.post(
                f"{VERIFIER_URL}/v1/verify/lab-03-resources",
                json={"suite_id": execution_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verified.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H03/verify")
async def verify_h03_sync_app(
    request: Request,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if await request.body():
        raise HTTPException(status_code=422, detail="verification inputs are server-owned")
    session_id = session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    suite_id = str(uuid.uuid4())
    execution_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            started = await client.post(
                f"{LAB03_URL}/v1/sync",
                json={"execution_id": execution_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {LAB03_TOKEN}"},
            )
            if started.status_code != 200:
                raise HTTPException(status_code=502, detail="H03 current ingestion did not start")
            early = await client.post(
                f"{LAB03_URL}/v1/search",
                json={"execution_id": execution_id, "phase": "early"},
                headers={"Authorization": f"Bearer {LAB03_TOKEN}"},
            )
            if early.status_code not in {200, 409}:
                raise HTTPException(status_code=502, detail="H03 early search returned an unexpected status")

            job_status = "STARTING"
            for _ in range(20):
                status_response = await client.get(
                    f"{LAB03_URL}/v1/status/{execution_id}",
                    headers={"Authorization": f"Bearer {LAB03_TOKEN}"},
                )
                if status_response.status_code != 200:
                    raise HTTPException(status_code=502, detail="H03 current job status is unavailable")
                job_status = status_response.json().get("status", "")
                if job_status == "COMPLETE":
                    break
                if job_status in {"FAILED", "STOPPED"}:
                    raise HTTPException(status_code=502, detail=f"H03 ingestion entered {job_status}")
                await asyncio.sleep(2)
            if job_status != "COMPLETE":
                raise HTTPException(status_code=504, detail="H03 ingestion did not complete in 40 seconds")

            final = await client.post(
                f"{LAB03_URL}/v1/search",
                json={"execution_id": execution_id, "phase": "final"},
                headers={"Authorization": f"Bearer {LAB03_TOKEN}"},
            )
            if final.status_code != 200:
                raise HTTPException(status_code=502, detail="H03 final search did not preserve normal retrieval")
            verified = await client.post(
                f"{VERIFIER_URL}/v1/verify/lab-03",
                json={
                    "suite_id": suite_id,
                    "execution_id": execution_id,
                    "started_at": started_at,
                },
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verified.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H04/provision")
async def provision_h04_guardrail(
    request: Request,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if await request.body():
        raise HTTPException(status_code=422, detail="provisioning inputs are server-owned")
    session_id = session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    execution_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            response = await client.post(
                f"{GATEWAY_URL}/v1/h04/provision",
                json={"execution_id": execution_id},
                headers={"Authorization": f"Bearer {H04_PROVISION_TOKEN}"},
            )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "control_center",
                        "stopped_stage": "h04_guardrail_provisioning",
                        "downstream_called": True,
                        "course_verdict": "ERR",
                        "next_check": "H04 Gateway 원시 오류와 전용 Guardrail 상태를 확인합니다.",
                    },
                )
            verified = await client.post(
                f"{VERIFIER_URL}/v1/verify/lab-04-resources",
                json={"suite_id": execution_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verified.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H04/verify")
async def verify_h04_guardrail_app(
    request: Request,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if await request.body():
        raise HTTPException(status_code=422, detail="verification inputs are server-owned")
    session_id = session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    suite_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    cases = []
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            for case_id in (
                "apply-normal",
                "apply-risk",
                "converse-normal",
                "converse-risk",
            ):
                execution_id = str(uuid.uuid4())
                case_started_at = datetime.now(timezone.utc).isoformat()
                response = await client.post(
                    f"{LAB04_URL}/v1/run",
                    json={
                        "execution_id": execution_id,
                        "started_at": case_started_at,
                        "case_id": case_id,
                    },
                    headers={"Authorization": f"Bearer {LAB04_TOKEN}"},
                )
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "successful_stage": "control_center",
                            "stopped_stage": "guided_h04_guardrail_app",
                            "downstream_called": False,
                            "course_verdict": "ERR",
                            "next_check": "H04 Guardrail 상태와 수강생 앱의 Gateway 요청을 확인합니다.",
                        },
                    )
                cases.append(
                    {
                        "case_id": case_id,
                        "execution_id": execution_id,
                        "started_at": case_started_at,
                    }
                )
            verified = await client.post(
                f"{VERIFIER_URL}/v1/verify/lab-04",
                json={"suite_id": suite_id, "started_at": started_at, "cases": cases},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verified.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H05/verify")
async def verify_h05_dialog_rail(
    request: Request,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if await request.body():
        raise HTTPException(status_code=422, detail="verification inputs are server-owned")
    session_id = session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    suite_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    cases = []
    try:
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            for case_id in (
                "contact-exact",
                "contact-paraphrase",
                "recovery-risk",
                "unsupported",
            ):
                execution_id = str(uuid.uuid4())
                case_started_at = datetime.now(timezone.utc).isoformat()
                response = await client.post(
                    f"{LAB05_URL}/v1/run",
                    json={
                        "execution_id": execution_id,
                        "started_at": case_started_at,
                        "case_id": case_id,
                    },
                    headers={"Authorization": f"Bearer {LAB05_TOKEN}"},
                )
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "successful_stage": "control_center",
                            "stopped_stage": "guided_h05_nemo_dialog",
                            "downstream_called": False,
                            "course_verdict": "ERR",
                            "next_check": "H05 image와 flows.co의 Colang 문법을 확인합니다.",
                        },
                    )
                cases.append(
                    {
                        "case_id": case_id,
                        "execution_id": execution_id,
                        "started_at": case_started_at,
                    }
                )

            evaluation = await client.post(
                f"{LAB05_URL}/v1/evaluate",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {LAB05_TOKEN}"},
            )
            if evaluation.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "guided_h05_nemo_dialog",
                        "stopped_stage": "nemo_topical_evaluation",
                        "downstream_called": False,
                        "course_verdict": "ERR",
                        "next_check": "NeMo Topical 평가 출력과 config 경로를 확인합니다.",
                    },
                )
            evaluation_id = evaluation.json().get("evaluation_id")
            if not evaluation_id:
                raise HTTPException(status_code=502, detail="H05 evaluation ID is missing")

            verified = await client.post(
                f"{VERIFIER_URL}/v1/verify/lab-05",
                json={
                    "suite_id": suite_id,
                    "started_at": started_at,
                    "cases": cases,
                    "evaluation_id": evaluation_id,
                },
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verified.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H06/verify")
async def verify_h06_python_action(
    request: Request,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if await request.body():
        raise HTTPException(status_code=422, detail="verification inputs are server-owned")
    session_id = session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    suite_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    case_ids = (
        "balance-read",
        "transfer-explicit",
        "transfer-prefixed",
        "unsupported",
    )
    executions = [
        {
            "execution_id": str(uuid.uuid4()),
            "case_id": case_id,
        }
        for case_id in case_ids
    ]
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            prepared = await client.post(
                f"{H06_PROVIDER_URL}/v1/suites",
                json={
                    "suite_id": suite_id,
                    "started_at": started_at,
                    "executions": executions,
                },
                headers={"Authorization": f"Bearer {H06_PROVIDER_CONTROL_TOKEN}"},
            )
            if prepared.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "control_center",
                        "stopped_stage": "h06_action_provider_prepare",
                        "downstream_called": False,
                        "course_verdict": "ERR",
                        "next_check": "H06 합성 Provider가 새 suite와 네 개의 일회 capability를 만들었는지 확인합니다.",
                    },
                )
            grants = prepared.json().get("cases")
            if not isinstance(grants, list) or [item.get("case_id") for item in grants] != list(case_ids):
                raise HTTPException(status_code=502, detail="H06 provider capabilities are incomplete")
            learner_cases = [
                {
                    "execution_id": item["execution_id"],
                    "case_id": item["case_id"],
                    "capability": item["capability"],
                }
                for item in grants
            ]
            executed = await client.post(
                f"{LAB06_URL}/v1/run",
                json={
                    "suite_id": suite_id,
                    "started_at": started_at,
                    "cases": learner_cases,
                },
                headers={"Authorization": f"Bearer {LAB06_TOKEN}"},
            )
            if executed.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "h06_action_provider_prepare",
                        "stopped_stage": "guided_h06_nemo_action",
                        "downstream_called": False,
                        "course_verdict": "ERR",
                        "next_check": "H06 image, Action 등록과 Colang 문법을 확인합니다.",
                    },
                )
            if executed.json().get("suite_id") != suite_id:
                raise HTTPException(status_code=502, detail="H06 suite receipt is missing")
            verified = await client.post(
                f"{VERIFIER_URL}/v1/verify/h06",
                json={
                    "suite_id": suite_id,
                    "started_at": started_at,
                },
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verified.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


async def close_h07_gateway_suite(suite_id: str) -> bool:
    """Close unused one-time grants even when the learner path fails."""
    try:
        async with httpx.AsyncClient(timeout=H07_CLOSE_TIMEOUT) as client:
            for attempt in range(3):
                response = await client.post(
                    f"{GATEWAY_URL}/v1/h07/suites/{suite_id}/close",
                    headers={"Authorization": f"Bearer {H07_GATEWAY_CONTROL_TOKEN}"},
                )
                if response.status_code == 200:
                    return response.json().get("suite_id") == suite_id
                if response.status_code != 409:
                    return False
                await asyncio.sleep(0.2 * (attempt + 1))
        return False
    except (httpx.RequestError, ValueError):
        return False


@app.post("/api/hands-on/H07/verify")
async def verify_h07_content_safety(
    request: Request,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if await request.body():
        raise HTTPException(status_code=422, detail="verification inputs are server-owned")
    session_id = session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    suite_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    prepare_attempted = False
    suite_closed = False
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            prepare_attempted = True
            prepared = await client.post(
                f"{GATEWAY_URL}/v1/h07/suites",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {H07_GATEWAY_CONTROL_TOKEN}"},
            )
            if prepared.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "control_center",
                        "stopped_stage": "h07_gateway_prepare",
                        "downstream_called": False,
                        "course_verdict": "ERR",
                        "next_check": "H07 Gateway가 두 요청과 역할별 일회 capability를 만들었는지 확인합니다.",
                    },
                )
            provider_cases = prepared.json().get("cases")
            expected_order = ["normal-phishing-defense", "risk-phishing-kit"]
            if not isinstance(provider_cases, list) or [
                item.get("case_id") for item in provider_cases
            ] != expected_order:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "h07_gateway_prepare",
                        "stopped_stage": "h07_capability_contract",
                        "downstream_called": True,
                        "course_verdict": "ERR",
                        "next_check": "H07 Gateway가 고정 순서의 두 Testcase를 만들었는지 확인합니다.",
                    },
                )
            learner_cases = []
            for item in provider_cases:
                roles = item.get("roles")
                if not isinstance(roles, dict) or set(roles) != {"content_safety", "main"}:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "successful_stage": "h07_gateway_prepare",
                            "stopped_stage": "h07_capability_contract",
                            "downstream_called": True,
                            "course_verdict": "ERR",
                            "next_check": "각 H07 Testcase에 Content Safety와 Main 역할 capability가 있는지 확인합니다.",
                        },
                    )
                learner_cases.append(
                    {
                        "case_id": item["case_id"],
                        "execution_id": item["execution_id"],
                        "content_safety_capability": roles["content_safety"]["capability"],
                        "main_capability": roles["main"]["capability"],
                    }
                )
            executed = await client.post(
                f"{LAB07_URL}/v1/run",
                json={
                    "suite_id": suite_id,
                    "started_at": started_at,
                    "cases": learner_cases,
                },
                headers={"Authorization": f"Bearer {LAB07_TOKEN}"},
            )
            if executed.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "h07_gateway_prepare",
                        "stopped_stage": "guided_h07_content_safety",
                        "downstream_called": True,
                        "course_verdict": "ERR",
                        "next_check": "H07 image, NeMo 0.22.0 설정과 입력 Rail 문법을 확인합니다.",
                    },
                )
            if executed.json().get("suite_id") != suite_id:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "guided_h07_content_safety",
                        "stopped_stage": "h07_learner_receipt",
                        "downstream_called": True,
                        "course_verdict": "ERR",
                        "next_check": "H07 learner가 현재 suite ID의 실행 영수증을 저장했는지 확인합니다.",
                    },
                )
            suite_closed = await close_h07_gateway_suite(suite_id)
            if not suite_closed:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "guided_h07_content_safety",
                        "stopped_stage": "h07_gateway_close",
                        "downstream_called": True,
                        "course_verdict": "ERR",
                        "next_check": "실행 중인 H07 역할 호출이 끝났고 사용하지 않은 capability가 닫혔는지 확인합니다.",
                    },
                )
            verified = await client.post(
                f"{VERIFIER_URL}/v1/verify/h07",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verified.json()
    except HTTPException:
        if prepare_attempted and not suite_closed:
            await close_h07_gateway_suite(suite_id)
        raise
    except httpx.RequestError as exc:
        if prepare_attempted and not suite_closed:
            await close_h07_gateway_suite(suite_id)
        raise HTTPException(
            status_code=502,
            detail={
                "successful_stage": "control_center",
                "stopped_stage": "h07_internal_service",
                "downstream_called": prepare_attempted,
                "course_verdict": "ERR",
                "next_check": "H07 Gateway·learner 상태와 suite가 닫혔는지 확인합니다.",
            },
        ) from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H22/verify")
async def verify_h22_mcp_server(
    request: Request,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if await request.body():
        raise HTTPException(status_code=422, detail="verification inputs are server-owned")
    session_id = session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            run_response = await client.post(
                f"{H22_HOST_URL}/v1/run-suite",
                headers={"Authorization": f"Bearer {H22_TOKEN}"},
            )
            if run_response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "control_center",
                        "stopped_stage": "mcp_host",
                        "downstream_called": False,
                        "course_verdict": "ERR",
                        "next_check": "H22 Host와 MCP Server 컨테이너 상태를 확인합니다.",
                    },
                )
            execution = run_response.json()
            verifier_response = await client.post(
                f"{VERIFIER_URL}/v1/verify/lab-22",
                json={
                    "suite_id": execution["suite_id"],
                    "started_at": execution["started_at"],
                },
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verifier_response.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verifier_response.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H21/verify")
async def verify_h21_agent_policy(
    request: Request,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if await request.body():
        raise HTTPException(status_code=422, detail="verification inputs are server-owned")
    session_id = session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            run_response = await client.post(
                f"{H21_HOST_URL}/v1/run-suite",
                headers={"Authorization": f"Bearer {H21_TOKEN}"},
            )
            if run_response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "control_center",
                        "stopped_stage": "agent_host",
                        "downstream_called": False,
                        "course_verdict": "ERR",
                        "next_check": "H21 Host·Provider·MCP Server 상태를 확인합니다.",
                    },
                )
            execution = run_response.json()
            verifier_response = await client.post(
                f"{VERIFIER_URL}/v1/verify/lab-21",
                json={
                    "suite_id": execution["suite_id"],
                    "started_at": execution["started_at"],
                },
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verifier_response.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verifier_response.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)
