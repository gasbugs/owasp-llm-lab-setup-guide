"""Same-origin learning UI orchestrator for the tenant 03 vertical slice."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import httpx
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field


ROOT = Path(__file__).parent
APP_VERSION = os.getenv("RELEASE_VERSION", os.getenv("APP_VERSION", "dev"))
SESSION_SECRET = os.environ["GUIDED_SESSION_SECRET"].encode()
LAB_URL = os.getenv("GUIDED_LAB01_URL", "http://guided-lab-01-nova:8000")
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


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=4000)
    max_output_tokens: int = Field(ge=1, le=512)
    run_kind: Literal["observe", "bounded"] = "observe"


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


def expected_digest(max_output_tokens: int) -> str:
    encoded = json.dumps(
        {
            "model_id": MODEL_ID,
            "inference_config": {
                "maxTokens": max_output_tokens,
                "temperature": 0.0,
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


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
        "exercise_started": False,
        "hint_level": 0,
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
        "course": {"tabs": 13, "activities": 22, "implemented_tabs": ["01-nova"]},
        "official_uis": [
            {
                "id": "nemo",
                "name": "NeMo Chat UI",
                "browser_url": NEMO_BROWSER_URL,
                "status": "ready",
                "boundary": "NeMo 단독 Rail 화면이며 파트 01 판정은 Control Center가 수행합니다.",
            },
            {
                "id": "bedrock",
                "name": "Amazon Bedrock Console",
                "browser_url": "https://console.aws.amazon.com/bedrock/home?region=us-east-1",
                "status": "external",
                "boundary": "AWS 로그인과 수강생 본인 계정 권한을 사용합니다.",
            },
        ],
        "exercise": {
            "started": session[1]["exercise_started"],
            "hint_level": session[1]["hint_level"],
        },
    }


async def execute(
    session_id: str, body: RunRequest, run_kind: Literal["observe", "bounded", "preflight"]
) -> dict:
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    execution_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    max_output_tokens = 2 if run_kind == "preflight" else body.max_output_tokens
    prompt = "Reply only OK" if run_kind == "preflight" else body.prompt
    lab_payload = {
        "execution_id": execution_id,
        "started_at": started_at,
        "prompt": prompt,
        "max_output_tokens": max_output_tokens,
        "run_kind": run_kind,
    }
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            lab_response = await client.post(
                f"{LAB_URL}/v1/run",
                json=lab_payload,
                headers={"Authorization": f"Bearer {LAB_TOKEN}"},
            )
            if lab_response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "control_center",
                        "stopped_stage": "lab_01_executor",
                        "downstream_called": False,
                        "course_verdict": "ERR",
                        "next_check": "Lab 01과 Bedrock Gateway 상태를 확인합니다.",
                    },
                )
            verifier_response = await client.post(
                f"{VERIFIER_URL}/v1/verify/lab-01",
                json={
                    "execution_id": execution_id,
                    "started_at": started_at,
                    "expected_config_digest": expected_digest(max_output_tokens),
                    "expected_max_output_tokens": max_output_tokens,
                    "run_kind": run_kind,
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
    return await execute(
        session[0],
        RunRequest(prompt="Reply only OK", max_output_tokens=2, run_kind="observe"),
        "preflight",
    )


@app.post("/api/labs/01-nova/run")
async def run_lab(
    body: RunRequest,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if body.run_kind == "bounded" and not session[1]["exercise_started"]:
        raise HTTPException(status_code=409, detail="exercise has not started")
    return await execute(session[0], body, body.run_kind)


@app.post("/api/labs/01-nova/exercise/start")
def start_exercise(session: tuple[str, dict] = Depends(require_csrf)) -> dict:
    session[1]["exercise_started"] = True
    session[1]["hint_level"] = 0
    return {
        "started": True,
        "scenario": "길어진 고객 상담 응답의 실제 Provider 출력 상한을 128 이하로 줄입니다.",
        "success_condition": "전달한 maxTokens와 AWS 사용량이 함께 확인되고 outputTokens가 선택한 상한을 넘지 않습니다.",
    }


@app.post("/api/labs/01-nova/exercise/hint")
def hint(session: tuple[str, dict] = Depends(require_csrf)) -> dict:
    if not session[1]["exercise_started"]:
        raise HTTPException(status_code=409, detail="exercise has not started")
    session[1]["hint_level"] = min(session[1]["hint_level"] + 1, 2)
    hints = {
        1: "응답 길이만 보지 말고 forwarded_parameters.maxTokens를 먼저 확인합니다.",
        2: "운영 상한은 128입니다. 더 작은 상한도 정상 응답이 유지되면 통과할 수 있습니다.",
    }
    return {"hint_level": session[1]["hint_level"], "hint": hints[session[1]["hint_level"]]}


@app.post("/api/labs/01-nova/exercise/reset")
def reset(session: tuple[str, dict] = Depends(require_csrf)) -> dict:
    session[1]["exercise_started"] = False
    session[1]["hint_level"] = 0
    return {"started": False, "message": "파트 01 선택값만 초기화했습니다."}
