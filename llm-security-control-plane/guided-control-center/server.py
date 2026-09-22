"""Same-origin learning UI orchestrator for the tenant 03 vertical slice."""

from __future__ import annotations

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
LAB_URL = os.getenv("GUIDED_LAB01_URL", "http://guided-student-app:8000")
VERIFIER_URL = os.getenv("GUIDED_VERIFIER_URL", "http://guided-evidence-verifier:8000")
LAB_TOKEN = os.environ["GUIDED_CONTROL_LAB01_TOKEN"]
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
            "implemented_hands_on": ["H01"],
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
            "service": "guided-student-app",
            "policy_path": "llm-security-control-plane/guided-labs/h01-nova-output-limit/policy.py",
            "compose_path": "examples/security-monitoring/compose.guided.yaml",
        },
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
                "requested_max_output_tokens": 2,
            }
        ]
        if suite_kind == "preflight"
        else [
            {
                "case_id": "normal-64",
                "scenario": "normal",
                "prompt": "GUIDED-H01-NORMAL: TLS 인증서 교체 절차를 세 문장으로 요약하세요.",
                "requested_max_output_tokens": 64,
            },
            {
                "case_id": "risk-512",
                "scenario": "risk",
                "prompt": "GUIDED-H01-RISK: 상담 절차를 출력 한계까지 상세히 작성하세요.",
                "requested_max_output_tokens": 512,
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
                    f"{LAB_URL}/v1/run",
                    json={
                        "execution_id": execution_id,
                        "started_at": started_at,
                        "prompt": definition["prompt"],
                        "requested_max_output_tokens": definition[
                            "requested_max_output_tokens"
                        ],
                        "scenario": definition["scenario"],
                    },
                    headers={"Authorization": f"Bearer {LAB_TOKEN}"},
                )
                if lab_response.status_code != 200:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "successful_stage": "control_center",
                            "stopped_stage": "guided_student_app",
                            "downstream_called": False,
                            "course_verdict": "ERR",
                            "next_check": "guided-student-app과 Bedrock Gateway 상태를 확인합니다.",
                        },
                    )
                cases.append(
                    {
                        "case_id": definition["case_id"],
                        "scenario": definition["scenario"],
                        "execution_id": execution_id,
                        "started_at": started_at,
                        "requested_max_output_tokens": definition[
                            "requested_max_output_tokens"
                        ],
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
                f"{LAB_URL}/v1/run",
                json={
                    "execution_id": execution_id,
                    "started_at": started_at,
                    "prompt": chat.prompt,
                    "requested_max_output_tokens": 512,
                    "scenario": "chat",
                },
                headers={"Authorization": f"Bearer {LAB_TOKEN}"},
            )
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail="guided student app chat failed")
        result = response.json()
        return {
            "activity_id": "H01",
            "execution_kind": "exploratory_chat",
            "graded": False,
            "execution_id": execution_id,
            "started_at": started_at,
            "stage_calls": [
                {"stage": "student_output_policy", "outcome": "completed"},
                {"stage": "bedrock_main", "outcome": "completed"},
            ],
            "result": result,
        }
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)
