"""Same-origin learning UI orchestrator for the tenant 03 vertical slice."""

from __future__ import annotations

import time
import asyncio
from contextvars import ContextVar
import hashlib
import base64
import hmac
import json
import os
import secrets
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field


EXPLORATION = ContextVar("guided_exploration", default=False)
PREVIEW_MESSAGE = ContextVar("guided_preview_message", default=None)
PREVIEW_CASE = ContextVar("guided_preview_case", default=None)
NATIVE_SESSION = ContextVar("guided_native_session", default=None)
DIAGNOSTIC_STATE = ContextVar("guided_diagnostic_state", default=None)


def clean_experience(value):
    # Keep native data; remove credentials and course-only decisions.
    excluded = {"access_token", "token", "capability", "authorization", "credential", "task_completed", "security_verdict", "course_verdict", "verified_by"}
    def clean(item):
        if isinstance(item, dict):
            return {k: clean(v) for k, v in item.items() if k.lower() not in excluded and not k.lower().endswith("_token")}
        if isinstance(item, list):
            return [clean(v) for v in item]
        return item
    return clean(value)


async def exploration_result(value):
    problem = EXPLORATION.get()
    if problem not in {"P02", "P03", "P04"}:
        async with httpx.AsyncClient(timeout=30, trust_env=False, follow_redirects=False) as reader:
            response = await reader.post(f"{VERIFIER_URL}/v1/exploration/{problem}",
                json={"execution": clean_experience(value)}, headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"})
        if response.status_code != 200:
            raise HTTPException(502, "실행 기록을 조회하지 못했습니다. 해당 미션 서비스 상태를 확인하세요.")
        value = response.json()
    return {"graded": False, "result": clean_experience(value)}


ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))
from progress import ProgressStore
from diagnostics import diagnosis

PROGRESS = ProgressStore(os.getenv("GUIDED_PROGRESS_DATABASE", ":memory:"))
P01_PATH = ROOT / "p01.json"
if not P01_PATH.exists():
    P01_PATH = ROOT.parent / "guided-contracts/p01.json"
P01_CONTRACT = json.loads(P01_PATH.read_text())
APP_VERSION = os.getenv("RELEASE_VERSION", os.getenv("APP_VERSION", "dev"))
SESSION_SECRET = os.environ["GUIDED_SESSION_SECRET"].encode()
ADMIN_ANSWERS = ROOT / "admin-answers"
LAB_URL = os.getenv("GUIDED_LAB01_URL", "http://guided-h01-gateway:8000")
LAB02_URL = os.getenv("GUIDED_LAB02_URL", "http://guided-h02-document-app:8000")
LAB03_URL = os.getenv("GUIDED_LAB03_URL", "http://guided-h03-sync-app:8000")
LAB04_URL = os.getenv("GUIDED_LAB04_URL", "http://guided-h04-guardrail-app:8000")
LAB05_URL = os.getenv("GUIDED_LAB05_URL", "http://guided-h05-nemo-dialog:8000")
LAB06_URL = os.getenv("GUIDED_LAB06_URL", "http://guided-h06-nemo-action:8000")
LAB07_URL = os.getenv("GUIDED_LAB07_URL", "http://guided-h07-content-safety:8000")
LAB08_URL = os.getenv("GUIDED_LAB08_URL", "http://guided-h08-self-check-input:8000")
LAB09_URL = os.getenv("GUIDED_LAB09_URL", "http://guided-h09-presidio-redaction:8000")
LAB10_URL = os.getenv("GUIDED_LAB10_URL", "http://guided-h10-self-check-output:8000")
LAB11_URL = os.getenv("GUIDED_LAB11_URL", "http://guided-h11-rag-provenance:8000")
LAB12_URL = os.getenv("GUIDED_LAB12_URL", "http://guided-h12-application-pipeline:8000")
LAB13_URL = os.getenv("GUIDED_LAB13_URL", "http://guided-h13-promptfoo:8000")
LAB14_URL = os.getenv("GUIDED_LAB14_URL", "http://guided-h14-garak:8000")
LAB15_URL = os.getenv("GUIDED_LAB15_URL", "http://guided-h15-pyrit:8000")
LAB16_URL = os.getenv("GUIDED_LAB16_URL", "http://guided-h16-policy-promotion:8000")
OBSERVABILITY_URL = os.getenv("GUIDED_OBSERVABILITY_URL", "http://guided-observability:8000")
H18_URL = os.getenv("GUIDED_H18_URL", "http://guided-h18-queries:8000")
H18_TOKEN = os.environ["GUIDED_CONTROL_H18_TOKEN"]
H19_URL = os.getenv("GUIDED_H19_URL", "http://guided-h19-investigation:8000")
H19_TOKEN = os.environ["GUIDED_CONTROL_H19_TOKEN"]
H20_URL = os.getenv("GUIDED_H20_URL", "http://guided-h20-alerts:8000")
H20_TOKEN = os.getenv("GUIDED_CONTROL_H20_TOKEN", "")
H17_URL = os.getenv("GUIDED_H17_URL", "http://guided-h17-telemetry:8000")
H17_TOKEN = os.environ["GUIDED_CONTROL_H17_TOKEN"]
H09_SINK_URL = os.getenv(
    "GUIDED_H09_SINK_URL", "http://guided-h09-delivery-sink:8000"
)
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
LAB08_TOKEN = os.environ["GUIDED_CONTROL_LAB08_TOKEN"]
LAB09_TOKEN = os.environ["GUIDED_CONTROL_LAB09_TOKEN"]
LAB10_TOKEN = os.environ["GUIDED_CONTROL_LAB10_TOKEN"]
LAB11_TOKEN = os.environ["GUIDED_CONTROL_LAB11_TOKEN"]
LAB12_TOKEN = os.environ["GUIDED_CONTROL_LAB12_TOKEN"]
LAB13_TOKEN = os.environ["GUIDED_CONTROL_LAB13_TOKEN"]
LAB14_TOKEN = os.environ["GUIDED_CONTROL_LAB14_TOKEN"]
LAB15_TOKEN = os.environ["GUIDED_CONTROL_LAB15_TOKEN"]
LAB16_TOKEN = os.environ["GUIDED_CONTROL_LAB16_TOKEN"]
OBSERVABILITY_TOKEN = os.environ["GUIDED_CONTROL_OBSERVABILITY_TOKEN"]
H09_SINK_CONTROL_TOKEN = os.environ["GUIDED_H09_SINK_CONTROL_TOKEN"]
H06_PROVIDER_CONTROL_TOKEN = os.environ["GUIDED_H06_PROVIDER_CONTROL_TOKEN"]
H07_GATEWAY_CONTROL_TOKEN = os.environ["GUIDED_H07_GATEWAY_CONTROL_TOKEN"]
H08_GATEWAY_CONTROL_TOKEN = os.environ["GUIDED_H08_GATEWAY_CONTROL_TOKEN"]
H22_TOKEN = os.environ["GUIDED_CONTROL_H22_TOKEN"]
H21_TOKEN = os.environ["GUIDED_CONTROL_H21_TOKEN"]
H02_PROVISION_TOKEN = os.environ["GUIDED_LAB02_PROVISION_TOKEN"]
H03_PROVISION_TOKEN = os.environ["GUIDED_LAB03_PROVISION_TOKEN"]
H04_PROVISION_TOKEN = os.environ["GUIDED_LAB04_PROVISION_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_CONTROL_VERIFIER_TOKEN"]
ALLOWED_HOSTS = set(
    os.getenv(
        "GUIDED_ALLOWED_HOSTS", "127.0.0.1:28097,localhost:28097,testserver"
    ).split(",")
)
ALLOWED_ORIGINS = set(
    os.getenv(
        "GUIDED_ALLOWED_ORIGINS",
        "http://127.0.0.1:28097,http://localhost:28097,http://testserver",
    ).split(",")
)
TIMEOUT = httpx.Timeout(130.0, connect=3.0)
PROVISION_TIMEOUT = httpx.Timeout(360.0, connect=3.0)
H07_CLOSE_TIMEOUT = httpx.Timeout(3.0, connect=1.0)
MODEL_ID = "us.amazon.nova-lite-v1:0"
NEMO_BROWSER_URL = os.getenv("GUIDED_NEMO_BROWSER_URL", "http://127.0.0.1:28192")
PROMPTFOO_BROWSER_URL = os.getenv("GUIDED_PROMPTFOO_BROWSER_URL", "http://127.0.0.1:25500")
PYRIT_BROWSER_URL = os.getenv("GUIDED_PYRIT_BROWSER_URL", "http://127.0.0.1:28098")
GRAFANA_BROWSER_URL = os.getenv("GUIDED_GRAFANA_BROWSER_URL", "http://127.0.0.1:23001/explore")
P20_GRAFANA_BROWSER_URL = os.getenv("GUIDED_P20_GRAFANA_BROWSER_URL", "http://127.0.0.1:23002/d/guided-p20")
SESSIONS: dict[str, dict] = {}
ACTIVE_SESSIONS: set[str] = set()
RESOURCE_ACTIONS: set[str] = set()
MAX_SESSIONS = 256
SESSION_COOKIE_SECONDS = 7 * 24 * 3600


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
        "connect-src http://127.0.0.1:28198 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"


app = FastAPI(title="LLM Security Guided Control Center", docs_url=None, redoc_url=None)


def practice_envelope(payload: dict, public_id: str) -> dict:
    """Expose the existing verifier result under its public Practice identity."""
    internal_id = "H" + public_id[1:]
    if payload.get("activity_id") != internal_id:
        return payload
    verdict = payload.get("course_verdict", "ERR")
    return {
        **payload,
        "activity_id": public_id,
        "internal_activity_id": internal_id,
        "security_verdict": verdict,
        "task_completed": payload.get("task_completed", verdict == "PASS"),
    }


@app.middleware("http")
async def boundary_middleware(request: Request, call_next):
    if request.headers.get("host", "") not in ALLOWED_HOSTS:
        response = JSONResponse(status_code=421, content={"detail": "host is not allowed"})
        security_headers(response)
        return response
    parts = request.url.path.strip("/").split("/")
    locked_problem = None
    if (request.method == "POST" and len(parts) == 4 and parts[:2] in (["api", "practice"], ["api", "hands-on"])
            and parts[2] in {"P02", "P03", "P04", "H02", "H03", "H04"}
            and parts[3] in {"verify", "provision", "delete-resources"}):
        try:
            session = session_from_cookie(request.cookies.get("guided_session"))
            require_csrf(request, request.headers.get("x-csrf-token"), session)
            locked_problem = "P" + parts[2][1:]
            if locked_problem in RESOURCE_ACTIONS:
                response = JSONResponse(status_code=409, content={"detail": "이 미션의 AWS 작업 또는 채점이 실행 중입니다."})
                security_headers(response)
                return response
            RESOURCE_ACTIONS.add(locked_problem)
        except HTTPException:
            locked_problem = None
    native_context = None
    native_state = None
    attempt = None
    if (request.method == "POST" and len(parts) == 4 and parts[:2] == ["api", "practice"]
            and parts[2] in {f"P{number:02d}" for number in range(1, 24)}
            and parts[3] == "verify"):
        try:
            session = session_from_cookie(request.cookies.get("guided_session"))
            require_csrf(request, request.headers.get("x-csrf-token"), session)
            if not await request.body():
                attempt = PROGRESS.begin(parts[2])
                if int(parts[2][1:]) >= 5:
                    native_state={"problem":parts[2],"suite_id":str(uuid.uuid4()),"phase":"running","cases":[],"total":None,"current_case":None}
                    session[1]["native_progress"]=native_state
                    session[1].pop("_native_target",None)
                    native_context=NATIVE_SESSION.set(session[1])
        except HTTPException:
            pass
    diagnostic_state = {}
    diagnostic_context = DIAGNOSTIC_STATE.set(diagnostic_state)
    try:
        response = await call_next(request)
    finally:
        DIAGNOSTIC_STATE.reset(diagnostic_context)
        if locked_problem:
            RESOURCE_ACTIONS.discard(locked_problem)
        if native_context is not None:
            native_state["phase"]="finished";native_state["current_case"]=None
            NATIVE_SESSION.reset(native_context)
    if (len(parts) == 4 and parts[:2] == ["api", "practice"]
            and parts[2] in {f"P{number:02d}" for number in range(1, 24)}
            and parts[3] == "verify" and response.status_code == 200):
        body = b"".join([chunk async for chunk in response.body_iterator])
        payload = practice_envelope(json.loads(body), parts[2])
        if attempt:
            PROGRESS.finish(parts[2], attempt, payload)
        headers = {key: value for key, value in response.headers.items()
                   if key.lower() != "content-length"}
        response = JSONResponse(content=payload, status_code=200, headers=headers,
                                background=response.background)
    problem = next((part for part in parts if part in {f"P{number:02d}" for number in range(24)}), None)
    if problem and response.headers.get("content-type", "").startswith("application/json"):
        raw = b"".join([chunk async for chunk in response.body_iterator]) if hasattr(response, "body_iterator") else response.body
        payload = json.loads(raw)
        hint = diagnosis(problem, response.status_code if response.status_code >= 400 else 502, diagnostic_state.get("diagnosis"))
        def annotate(value):
            if isinstance(value, dict):
                if value.get("status") == "ERR" or value.get("course_verdict") == "ERR":
                    value.setdefault("diagnosis", hint)
                for child in list(value.values()):
                    if child is not hint: annotate(child)
            elif isinstance(value, list):
                for child in value: annotate(child)
        annotate(payload)
        if response.status_code >= 400:
            payload["diagnosis"] = hint
        headers = {key: value for key, value in response.headers.items() if key.lower() != "content-length"}
        response = JSONResponse(content=payload, status_code=response.status_code, headers=headers, background=response.background)
    security_headers(response)
    return response


@app.get("/", response_class=HTMLResponse)
def index(request: Request, mode: str | None = None) -> Response:
    session = None
    try:
        session = session_from_cookie(request.cookies.get("guided_session"))
    except HTTPException:
        pass
    if session is None:
        while len(SESSIONS) >= MAX_SESSIONS:
            oldest_idle = next(
                (candidate for candidate in SESSIONS if candidate not in ACTIVE_SESSIONS),
                None,
            )
            if oldest_idle is None:
                raise HTTPException(status_code=503, detail="all guided sessions are busy")
            SESSIONS.pop(oldest_idle, None)
        session_id = secrets.token_urlsafe(24)
        previous_id, separator, signature = request.cookies.get("guided_session", "").partition(".")
        expected = hmac.new(SESSION_SECRET, previous_id.encode(), hashlib.sha256).hexdigest()
        if previous_id and separator and hmac.compare_digest(signature, expected):
            session_id = previous_id
        state = {
            "csrf": secrets.token_urlsafe(24),
            "p00_token": secrets.token_urlsafe(32),
            "admin": False,
        }
        SESSIONS[session_id] = state
        session = (session_id, state)
    session_id, state = session
    if mode == "admin":
        state["admin"] = True
    else:
        state["admin"] = False
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
        max_age=SESSION_COOKIE_SECONDS,
    )
    return response


@app.get("/fonts/IBMPlexMono-SemiBold.woff2")
def home_numeric_font() -> FileResponse:
    return FileResponse(ROOT / "fonts/IBMPlexMono-SemiBold.woff2", media_type="font/woff2")


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


@app.get("/api/progress")
async def progress(session: tuple[str, dict] = Depends(require_session)) -> dict:
    records = PROGRESS.history()
    async with httpx.AsyncClient(timeout=3, follow_redirects=False, trust_env=False) as client:
        async def inspect(record):
            state = "recheck"
            reason = "새 검증이나 준비를 시작했습니다. 다시 검증하세요."
            if not record['needs_check']:
                reason = "현재 실행본을 확인하지 못했습니다. 다시 검증하세요."
                try:
                    response = await client.get(
                        f"{VERIFIER_URL}/v1/progress/{record['problem']}/build",
                        headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"})
                    current = response.json().get('source_digest') if response.status_code == 200 else None
                    if record['digest'] and current == record['digest']:
                        state, reason = "completed", "통과한 코드와 현재 실행본이 같습니다."
                    elif current and record['digest']:
                        reason = "실행본이 바뀌었습니다. 현재 구현을 다시 검증하세요."
                        PROGRESS.mark_changed(record['problem'], record['execution'])
                except (httpx.HTTPError, ValueError, AttributeError):
                    pass
            return {**{key: record[key] for key in ('problem', 'execution', 'completed_at')},
                    'state': state, 'reason': reason}
        return {'scope': 'installation', 'reset_generation': PROGRESS.reset_generation(), 'records': await asyncio.gather(*(inspect(r) for r in records))}


@app.post("/api/session/refresh")
def refresh_session(response: Response, session: tuple[str, dict] = Depends(require_csrf)) -> dict:
    response.set_cookie("guided_session", sign(session[0]), httponly=True,
                        samesite="strict", secure=False, path="/", max_age=SESSION_COOKIE_SECONDS)
    return {"refresh_after_seconds": 60, "cookie_max_age": SESSION_COOKIE_SECONDS}


@app.get("/api/bootstrap")
def bootstrap(session: tuple[str, dict] = Depends(require_session)) -> dict:
    payload = {
        "copyable_code_blocks": os.environ.get("GUIDED_COPYABLE_CODE_BLOCKS", "true").lower() in {"1", "true", "yes", "on"},
        "resource_total_steps": RESOURCE_TOTAL_STEPS, "csrf_token": session[1]["csrf"],
        "p00_submission_token": session[1]["p00_token"],
        "admin_mode": bool(session[1].get("admin")),
        "reset_generation": PROGRESS.reset_generation(),
        "workspace": "practice",
        "course": {
            "tabs": 13,
            "practices": 23,
            "practice_ids": [f"P{number:02d}" for number in range(1, 24)],
            "execution_ids": {f"P{number:02d}": f"H{number:02d}" for number in range(1, 24)},
            "hands_on": 23,
            "implemented_hands_on": [f"H{number:02d}" for number in range(1, 24)],
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
            {"id": "promptfoo", "name": "Promptfoo Viewer", "browser_url": PROMPTFOO_BROWSER_URL, "status": "ready", "boundary": "H13 native evaluation을 살펴보는 공식 UI이며 PASS 판정은 별도 verifier가 수행합니다."},
            {"id": "pyrit", "name": "PyRIT Frontend", "browser_url": PYRIT_BROWSER_URL, "status": "ready", "boundary": "PyRIT 대화를 탐색하는 공식 UI이며 실제 영향 재현은 H15 verifier가 수행합니다."},
            {"id": "grafana", "name": "Grafana Explore", "browser_url": GRAFANA_BROWSER_URL, "status": "ready", "boundary": "원시 제품 API를 먼저 확인한 뒤 같은 신호를 화면에서 비교합니다."},
            {"id": "p20-grafana", "name": "P20 Grafana", "browser_url": P20_GRAFANA_BROWSER_URL, "status": "ready", "boundary": "P20 전용 대시보드입니다. p20-reader 계정으로 현재 적용한 패널을 확인합니다. 화면만 열었다고 과제가 완료되지는 않습니다."},
        ],
        "learner_app": {
            "hands_on_id": "H01",
            "service": "guided-h01-gateway",
            "source_path": "llm-security-control-plane/guided-labs/h01-bedrock-gateway/learner.py",
            "compose_path": "examples/security-monitoring/compose.guided.yaml",
        },
        "learner_apps": [
            {"hands_on_id":"H23", "service":"guided-model-call", "source_path":"llm-security-control-plane/guided-labs/h23-model-call/learner.py"},
            {
                "hands_on_id": "H01",
                "service": "guided-h01-gateway",
                "source_path": "llm-security-control-plane/guided-labs/h01-bedrock-gateway/learner.py",
            },
            {
                "hands_on_id": "H02",
                "service": "guided-h02-document-app",
                "source_path": "llm-security-control-plane/guided-labs/h02-document-ingestion/learner.py",
            },
            {
                "hands_on_id": "H03",
                "service": "guided-h03-sync-app",
                "source_path": "llm-security-control-plane/guided-labs/h03-ingestion-search/learner.py",
            },
            {
                "hands_on_id": "H04",
                "service": "guided-h04-guardrail-app",
                "source_path": "llm-security-control-plane/guided-labs/h04-bedrock-guardrail/learner.py",
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
                "hands_on_id": "H08",
                "service": "guided-h08-self-check-input",
                "source_path": "llm-security-control-plane/guided-labs/h08-self-check-input/config/prompts.yml",
            },
            {
                "hands_on_id": "H09",
                "service": "guided-h09-presidio-redaction",
                "source_path": "llm-security-control-plane/guided-labs/h09-presidio-redaction/policy.py",
            },
            {
                "hands_on_id": "H10",
                "service": "guided-h10-self-check-output",
                "source_path": "llm-security-control-plane/guided-labs/h10-self-check-output/config/prompts.yml",
            },
            {
                "hands_on_id": "H11",
                "service": "guided-h11-rag-provenance",
                "source_path": "llm-security-control-plane/guided-labs/h11-rag-provenance/policy.py",
            },
            {
                "hands_on_id": "H12",
                "service": "guided-h12-application-pipeline",
                "source_path": "llm-security-control-plane/guided-labs/h12-application-pipeline/pipeline.py",
            },
            {
                "hands_on_id": "H13",
                "service": "guided-h13-promptfoo",
                "source_path": "llm-security-control-plane/guided-labs/h13-promptfoo/promptfooconfig.yaml",
            },
            {"hands_on_id": "H14", "service": "guided-h14-garak", "source_path": "llm-security-control-plane/guided-labs/h14-garak/garak-config.yaml"},
            {"hands_on_id": "H15", "service": "guided-h15-pyrit", "source_path": "llm-security-control-plane/guided-labs/h15-pyrit/attack.py"},
            {"hands_on_id": "H16", "service": "guided-h16-policy-promotion", "source_path": "llm-security-control-plane/guided-labs/h16-policy-promotion/policy.py"},
            {"hands_on_id": "H17", "service": "guided-h17-telemetry", "source_path": "llm-security-control-plane/guided-labs/h17-telemetry/instrumentation.py"},
            {"hands_on_id": "H18", "service": "guided-h18-queries", "source_path": "llm-security-control-plane/guided-labs/h18-product-queries/queries.yaml"},
            {"hands_on_id": "H19", "service": "guided-h19-investigation", "source_path": "llm-security-control-plane/guided-labs/h19-incident-investigation/investigation.py"},
            {"hands_on_id": "H20", "service": "guided-h20-alerts", "source_path": "llm-security-control-plane/guided-labs/h20-alert-dashboard/rules.yaml"},
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


    for item in [payload['learner_app'], *payload['learner_apps']]:
        item['internal_activity_id'] = item['hands_on_id']
        item['practice_id'] = 'P' + item['hands_on_id'][1:]
    return payload


@app.get("/api/admin/answers/{problem}")
def admin_answer(problem: str, session: tuple[str, dict] = Depends(require_session)) -> dict:
    if not session[1].get("admin"):
        raise HTTPException(status_code=403, detail="admin mode is required")
    if problem not in {f"P{number:02d}" for number in range(24)}:
        raise HTTPException(status_code=404, detail="answer does not exist")
    answer_path = ADMIN_ANSWERS / f"{problem}.md"
    if not answer_path.is_file():
        raise HTTPException(status_code=404, detail="answer does not exist")
    return {"problem": problem, "answer": answer_path.read_text(encoding="utf-8")}


async def execute_suite(session_id: str, suite_kind: str) -> dict:
    def incomplete(stage: str, reason: str) -> dict:
        return {
            "activity_id": "P01", "internal_activity_id": "H01",
            "contract_version": P01_CONTRACT["contract_version"],
            "task_completed": False, "security_verdict": "ERR", "course_verdict": "ERR",
            "successful_stage": "control_center", "stopped_stage": stage,
            "downstream_called": None, "stage_calls": [], "reason": reason,
            "next_check": "P01 원시 응답의 중단 위치와 해당 서비스 로그를 확인합니다.",
        }

    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    suite_id = str(uuid.uuid4())
    suite_started_at = datetime.now(timezone.utc).isoformat()
    definitions = P01_CONTRACT["preflight" if suite_kind == "preflight" else "cases"]
    cases = []
    progress = {"suite_id": suite_id, "total": len(definitions), "cases": [], "phase": "running"}
    SESSIONS[session_id]["case_progress"] = progress
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            for definition in definitions:
                execution_id = str(uuid.uuid4())
                started_at = datetime.now(timezone.utc).isoformat()
                progress["current_case"] = {"number": len(progress["cases"]) + 1, "case_id": definition["case_id"], "status": "실행 중", "started_at": started_at}
                case_started = time.monotonic()
                client_id = f"{definition['client_id']}-{suite_id[:8]}"
                lab_response = await client.post(
                    f"{LAB_URL}/v1/chat",
                    json={
                        "execution_id": execution_id,
                        "started_at": started_at,
                        "scenario": definition["scenario"],
                        "client_id": client_id,
                        **definition["body"],
                    },
                    headers={"Authorization": f"Bearer {LAB_TOKEN}"},
                )
                progress["cases"].append({
                    "number": len(progress["cases"]) + 1,
                    "case_id": definition["case_id"],
                    "status": "PASS" if lab_response.status_code == definition["expected_status"] else "ERR",
                    "input": definition["body"],
                    "scenario": definition["scenario"],
                    "expected_status": definition["expected_status"],
                    "observed_status": lab_response.status_code,
                    "elapsed_seconds": round(time.monotonic() - case_started, 2),
                })
                progress["current_case"] = None
                if lab_response.status_code != definition["expected_status"]:
                    failure = incomplete(
                        "guided_h01_gateway",
                        f"{definition['case_id']}: Gateway HTTP {lab_response.status_code}; "
                        "요청 처리 결과가 계약과 달라 검증을 중단했습니다. 모델 호출 여부는 아직 확인되지 않았습니다.",
                    )
                    try:
                        detail = lab_response.json().get("detail")
                        code = detail.get("provider_error") if isinstance(detail, dict) else None
                    except (ValueError, AttributeError):
                        code = None
                    guidance = {
                        "credentials_missing": ("Gateway가 AWS 로그인 정보를 찾지 못했습니다.", "Gateway의 AWS 설정 파일 연결과 AWS_PROFILE을 확인합니다."),
                        "credentials_invalid": ("AWS가 로그인 정보를 받아들이지 않았습니다.", "연결한 AWS 프로필의 자격 증명이 유효한지 확인합니다."),
                        "access_denied": ("AWS가 모델 호출 권한을 거부했습니다.", "현재 AWS 계정의 Bedrock 호출 권한과 모델 사용 권한을 확인합니다."),
                        "model_unavailable": ("요청한 모델을 현재 사용할 수 없습니다.", "Gateway의 리전과 모델 ID, 해당 모델의 사용 가능 상태를 확인합니다."),
                    }
                    if lab_response.status_code == 502 and isinstance(code, str) and code in guidance:
                        reason, next_check = guidance[code]
                        failure.update(provider_error=code, reason=reason + " 연결 확인을 완료하지 못했습니다. 모델 실행 완료 여부는 확인되지 않았습니다.", next_check=next_check)
                    failed_case = {
                        **progress["cases"][-1],
                        "status": "ERR",
                        "case_verified": False,
                        "reason": failure["reason"],
                    }
                    remaining = [
                        {"case_id": item["case_id"], "status": "미실행", "reason": "앞 케이스 실패로 중단"}
                        for item in definitions[len(progress["cases"]):]
                    ]
                    failure["result"] = {"cases": [failed_case, *remaining]}
                    progress["cases"] = failure["result"]["cases"]
                    progress["verdict"] = "ERR"
                    return failure
                cases.append(
                    {
                        "case_id": definition["case_id"],
                        "scenario": definition["scenario"],
                        "client_id": client_id,
                        "execution_id": execution_id,
                        "started_at": started_at,
                        "requested_max_output_tokens": definition["body"].get("max_output_tokens"),
                        "expected_status": definition["expected_status"],
                        "observed_status": lab_response.status_code,
                    }
                )
            progress["phase"] = "verifying"
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
            raise HTTPException(status_code=502, detail=incomplete(
                "evidence_verifier", "요청 실행 뒤 검증기의 정상 응답을 받지 못했습니다. 과제 완료를 확인할 수 없습니다.",
            ))
        result = verifier_response.json()
        sent = {definition["case_id"]: definition for definition in definitions}
        for record in result.get("result", {}).get("cases", []):
            if record.get("case_id") in sent:
                record["input"] = sent[record["case_id"]]["body"]
                record["scenario"] = sent[record["case_id"]]["scenario"]
        progress["verdict"] = result.get("security_verdict", "ERR")
        return result
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=incomplete(
            "internal_transport", "내부 서비스 통신이 끊겨 실행 결과를 확인할 수 없습니다.",
        )) from exc
    finally:
        progress["phase"] = "finished"
        progress["current_case"] = None
        ACTIVE_SESSIONS.discard(session_id)


@app.get("/api/test-progress/P01")
async def case_progress(session: tuple[str, dict] = Depends(require_session)) -> dict:
    return session[1].get("case_progress", {"suite_id": None, "cases": [], "phase": "idle"})


@app.get("/api/test-progress/P02")
async def p02_case_progress(session: tuple[str, dict] = Depends(require_session)) -> dict:
    state = session[1].get("p02_case_progress")
    if not state:
        return {"suite_id": None, "cases": [], "phase": "idle", "total": 22}
    if state["phase"] != "running":
        if not state.get("cases"):
            try:
                async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
                    response = await client.get(f"{VERIFIER_URL}/v1/progress/p02/{state['suite_id']}",
                                                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"})
                if response.status_code == 200 and response.json().get("suite_id") == state["suite_id"]:
                    return {**response.json(), "verdict": state.get("verdict", "ERR")}
            except httpx.HTTPError:
                pass
        return state
    async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
        response = await client.get(f"{LAB02_URL}/v1/progress/{state['suite_id']}",
                                    headers={"Authorization": f"Bearer {LAB02_TOKEN}"})
    if response.status_code == 404:
        return state
    if response.status_code != 200:
        raise HTTPException(502, "P02 progress unavailable")
    payload = response.json()
    if payload.get("suite_id") != state["suite_id"]:
        raise HTTPException(502, "P02 progress mismatch")
    if payload.get("phase") == "verifying":
        async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
            verified = await client.get(f"{VERIFIER_URL}/v1/progress/p02/{state['suite_id']}",
                                        headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"})
        if verified.status_code == 200 and verified.json().get("suite_id") == state["suite_id"]:
            return verified.json()
    return payload


@app.post("/api/provider-preflight")
async def provider_preflight(
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    return await execute_suite(session[0], "preflight")


@app.post("/api/hands-on/H01/verify")
@app.post("/api/practice/P01/verify")
async def verify_learner_app(
    request: Request,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if await request.body():
        raise HTTPException(status_code=422, detail="verification inputs are server-owned")
    return await execute_suite(session[0], "hands_on")


@app.post("/api/practice/P00/check")
async def check_tutorial(request: Request) -> dict:
    authorization = request.headers.get("authorization", "")
    token = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
    match = next(((key, value) for key, value in SESSIONS.items()
                  if token and hmac.compare_digest(token, value.get("p00_token", ""))), None)
    if match is None:
        raise HTTPException(status_code=401, detail="P00 제출 Token이 없거나 만료됐습니다. 화면을 새로고침하고 제출 명령을 다시 복사하세요.")
    session_id, session = match
    raw = await request.body()
    if len(raw) > 4096:
        raise HTTPException(status_code=413, detail="요청 파일을 4096바이트 이내로 작성하세요.")
    document = None
    try:
        document = json.loads(raw)
        parsed = True
    except (ValueError, UnicodeDecodeError):
        parsed = False
    is_object = parsed and isinstance(document, dict)
    checks = [
        ("JSON 객체 형식", parsed, is_object, "JSON 객체", type(document).__name__ if parsed else "JSON 형식 오류"),
        ("필드 이름과 개수", is_object, is_object and set(document) == {"message", "max_tokens"}, ["message", "max_tokens"], list(document) if is_object else None),
        ("질문 문장", is_object, is_object and document.get("message") == "계정 보안을 위한 조언을 한 문장으로 알려 주세요.", "계정 보안을 위한 조언을 한 문장으로 알려 주세요.", document.get("message") if is_object else None),
        ("출력 상한의 자료형과 값", is_object, is_object and type(document.get("max_tokens")) is int and document.get("max_tokens") == 64, {"type": "int", "value": 64}, {"type": type(document.get("max_tokens")).__name__, "value": document.get("max_tokens")} if is_object else None),
    ]
    cases = []
    for name, executed, passed, expected, actual in checks:
        case = {"case_id": name, "expected": expected, "actual": actual}
        if executed or name == "JSON 객체 형식":
            case["case_verified"] = bool(passed)
        else:
            case["status"] = "미실행"
        cases.append(case)
    valid = all(case.get("case_verified") is True for case in cases)
    result = {"completed": valid, "cases": cases, "upstream_called": False,
              "feedback": "네 가지 요청 검사를 통과했습니다." if valid else "JSON 객체, 두 필드의 이름, 질문 문장, 숫자 max_tokens=64를 확인하세요."}
    if parsed:
        result["received"] = document
    else:
        result["feedback"] = "JSON 형식 오류입니다. 파일의 큰따옴표와 쉼표를 확인하세요."
    if result["completed"]:
        PROGRESS.complete_tutorial(hmac.new(SESSION_SECRET, session_id.encode(), hashlib.sha256).hexdigest())
    session["p00_result"] = result
    return result


@app.get("/api/practice/P00/result")
async def tutorial_result(session: tuple[str, dict] = Depends(require_session)) -> dict:
    owner = hmac.new(SESSION_SECRET, session[0].encode(), hashlib.sha256).hexdigest()
    if "p00_result" not in session[1] and PROGRESS.tutorial_completed(owner):
        return {"completed": True, "upstream_called": False, "feedback": "저장된 P00 완료 기록을 불러왔습니다."}
    return session[1].get("p00_result", {"completed": False, "feedback": "아직 제출한 파일이 없습니다. 왼쪽의 제출 명령을 실행하세요."})


@app.post("/api/hands-on/H01/chat")
@app.post("/api/practice/P01/chat")
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
                    "client_id": "chat-" + hashlib.sha256(session_id.encode()).hexdigest()[:32],
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


RESOURCE_TOTAL_STEPS = {"P02": {"prepare": 11, "delete": 9},
                        "P03": {"prepare": 13, "delete": 9}, "P04": {"prepare": 6, "delete": 4}}


def completed_resource_progress(problem, operation_id, action):
    total = RESOURCE_TOTAL_STEPS[problem][action]
    return {"practice_id": problem, "operation_id": operation_id, "action": action,
            "current": total, "total": total, "state": "completed", "title": "최종 응답 확인",
            "description": "AWS 자원 작업의 최종 응답을 확인했습니다. 미션 채점은 별도로 실행합니다."}


@app.get("/api/resource-progress/{problem}")
async def read_resource_operation(problem: str, request: Request):
    session_id, data = session_from_cookie(request.cookies.get("guided_session"))
    if problem not in RESOURCE_TOTAL_STEPS:
        raise HTTPException(404, detail="unsupported resource progress")
    operation = data.get("resource_operation")
    if not operation or operation["problem"] != problem:
        return {"state": "idle"}
    tokens = {"P02": H02_PROVISION_TOKEN, "P03": H03_PROVISION_TOKEN, "P04": H04_PROVISION_TOKEN}
    async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
        response = await client.get(f"{GATEWAY_URL}/v1/resource-progress/{problem}/{operation['operation_id']}",
                                   headers={"Authorization": f"Bearer {tokens[problem]}"})
    if response.status_code != 200:
        raise HTTPException(502, detail="resource progress unavailable")
    result = response.json()
    if result.get("operation_id") != operation["operation_id"]:
        raise HTTPException(502, detail="resource progress operation mismatch")
    return result


@app.post("/api/practice/P02/delete-resources")
@app.post("/api/practice/P03/delete-resources")
@app.post("/api/practice/P04/delete-resources")
async def delete_practice_resources(request: Request,
                                    session: tuple[str, dict] = Depends(require_csrf)) -> dict:
    problem = request.url.path.split("/")[3]
    tokens = {"P02": H02_PROVISION_TOKEN, "P03": H03_PROVISION_TOKEN, "P04": H04_PROVISION_TOKEN}
    if problem not in tokens:
        raise HTTPException(404, detail="this mission has no AWS deletion action")
    if await request.body():
        raise HTTPException(422, detail="resource identifiers are server-owned")
    session_id = session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    operation = str(uuid.uuid4())
    session[1]["resource_operation"] = {"problem": problem, "operation_id": operation}
    try:
        async with httpx.AsyncClient(timeout=480, trust_env=False) as client:
            response = await client.post(f"{GATEWAY_URL}/v1/resource-lifecycle/{problem}/delete",
                json={"operation_id": operation}, headers={"Authorization": f"Bearer {tokens[problem]}"})
        if response.status_code != 200:
            try:
                reason = response.json().get("detail", "Gateway deletion failed")
            except ValueError:
                reason = "Gateway deletion response could not be parsed"
            raise HTTPException(response.status_code if response.status_code == 409 else 502,
                detail={"activity_id": problem, "operation_id": operation,
                        "stopped_stage": "aws_resource_deletion", "reason": reason,
                        "next_check": "진행 중인 작업·자원 소유권·AWS 삭제 권한을 확인하세요."})
        result = response.json()
        if result.get("practice_id") != problem or result.get("operation_id") != operation or result.get("state") != "deleted":
            raise HTTPException(502, detail="resource deletion response mismatch")
        return {"activity_id": problem, "operation_id": operation, "resource_deleted": True, "resource_progress": completed_resource_progress(problem, operation, "delete"),
                "task_completed": False, "deletion": result,
                "next_check": "미션 전용 AWS 자원을 삭제했습니다. 다시 실습하려면 AWS 자원 준비를 실행하세요."}
    except httpx.RequestError as exc:
        raise HTTPException(502, detail="AWS 삭제 응답을 확인하지 못했습니다. 일부 자원이 남아 있을 수 있습니다.") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H02/provision")
@app.post("/api/practice/P02/provision")
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
    session[1]["resource_operation"] = {"problem": 'P02', "operation_id": execution_id}
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
        verified = verifier_response.json()
        if verified.get("course_verdict") != "PASS":
            raise HTTPException(502, detail="AWS resource readiness could not be verified")
        return {"activity_id": "P02", "operation_id": execution_id,
                "resource_ready": True, "resource_progress": completed_resource_progress("P02", execution_id, "prepare"), "task_completed": False,
                "preparation": {"state": "ready", "resources": provision_response.json()},
                "next_check": "AWS 자원을 준비했습니다. 코드를 적용한 뒤 미션 채점을 실행하세요."}
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H02/verify")
@app.post("/api/practice/P02/verify")
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
    progress = {"suite_id": suite_id, "phase": "running", "cases": [], "total": 22}
    session[1]["p02_case_progress"] = progress
    try:
        async with httpx.AsyncClient(timeout=210, follow_redirects=False, trust_env=False) as client:
            response = await client.post(
                f"{LAB02_URL}/v1/run", json={"suite_id": suite_id},
                headers={"Authorization": f"Bearer {LAB02_TOKEN}"},
            )
            if response.status_code != 200 or response.json().get("suite_id") != suite_id:
                raise ValueError("P02 runner response unavailable")
            if EXPLORATION.get():
                return await exploration_result(response.json())
            verifier_response = await client.post(
                f"{VERIFIER_URL}/v1/verify/p02",
                json={"suite_id": suite_id},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verifier_response.status_code != 200:
            raise ValueError("P02 verifier unavailable")
        result = verifier_response.json()
        if (result.get("activity_id") != "P02"
                or result.get("execution_id") != suite_id
                or result.get("contract_version") != "p02-document-v1"
                or result.get("verified_by") != "guided-evidence-verifier"
                or type(result.get("task_completed")) is not bool
                or result.get("security_verdict") not in {"PASS", "ERR"}
                or result.get("course_verdict") != result["security_verdict"]
                or result["task_completed"] != (result["security_verdict"] == "PASS")):
            raise ValueError("P02 verifier response mismatch")
        progress.update(phase="finished", current_case=None, verdict=result["security_verdict"],
                        cases=result.get("result", {}).get("cases", []))
        return result
    except (httpx.RequestError, ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(status_code=502, detail={"task_completed": False, "security_verdict": "ERR",
            "course_verdict": "ERR", "next_check": "P02 실행 서버와 Gateway 기록을 확인하세요. 통신 오류만으로 호출이 없었다고 판단할 수 없습니다."}) from exc
    finally:
        progress["phase"] = "finished"
        progress["current_case"] = None
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H03/provision")
@app.post("/api/practice/P03/provision")
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
    operation_id = str(uuid.uuid4())
    session[1]["resource_operation"] = {"problem": 'P03', "operation_id": operation_id}
    try:
        async with httpx.AsyncClient(timeout=480, follow_redirects=False, trust_env=False) as client:
            response = await client.post(
                f"{GATEWAY_URL}/v1/p03/resources/prepare", json={"operation_id": operation_id},
                headers={"Authorization": f"Bearer {H03_PROVISION_TOKEN}"},
            )
        result = response.json()
        if (response.status_code != 200 or result.get("practice_id") != "P03"
                or result.get("operation_id") != operation_id or result.get("state") != "ready"
                or not isinstance(result.get("resources"), dict)
                or result["resources"].get("provider_mode") != "aws"
                or not isinstance(result.get("evidence"), dict)):
            raise ValueError("P03 preparation response mismatch")
        return {"activity_id": "P03", "operation_id": operation_id, "resource_ready": True, "resource_progress": completed_resource_progress("P03", operation_id, "prepare"),
                "task_completed": False, "preparation": result,
                "next_check": "P03 전용 문서의 동기화가 끝났습니다. 함수를 작성·빌드한 뒤 구현 검증을 실행하세요. 자원 준비는 과제 통과가 아닙니다."}
    except (httpx.RequestError, ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(status_code=502, detail={"task_completed": False, "security_verdict": "ERR",
            "course_verdict": "ERR", "activity_id": "P03", "operation_id": operation_id,
            "next_check": "P03 준비 기록과 AWS 자원 상태를 확인하세요. 오류가 나도 일부 자원이나 동기화 작업이 남아 있을 수 있습니다."}) from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H03/verify")
@app.post("/api/practice/P03/verify")
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
    try:
        async with httpx.AsyncClient(timeout=210, follow_redirects=False, trust_env=False) as client:
            response = await client.post(
                f"{LAB03_URL}/v1/run", json={"suite_id": suite_id},
                headers={"Authorization": f"Bearer {LAB03_TOKEN}"},
            )
            if response.status_code != 200 or response.json().get("suite_id") != suite_id:
                raise ValueError("P03 runner response unavailable")
            if EXPLORATION.get():
                return await exploration_result(response.json())
            verifier_response = await client.post(
                f"{VERIFIER_URL}/v1/verify/p03",
                json={"suite_id": suite_id},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verifier_response.status_code != 200:
            raise ValueError("P03 verifier unavailable")
        result = verifier_response.json()
        if (result.get("activity_id") != "P03"
                or result.get("execution_id") != suite_id
                or result.get("contract_version") != "p03-search-v1"
                or result.get("verified_by") != "guided-evidence-verifier"
                or type(result.get("task_completed")) is not bool
                or result.get("security_verdict") not in {"PASS", "ERR"}
                or result.get("course_verdict") != result["security_verdict"]
                or result["task_completed"] != (result["security_verdict"] == "PASS")):
            raise ValueError("P03 verifier response mismatch")
        return result
    except (httpx.RequestError, ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(status_code=502, detail={"task_completed": False, "security_verdict": "ERR",
            "course_verdict": "ERR", "next_check": "P03 실행 서버와 Gateway 기록을 확인하세요. 통신 오류만으로 호출이 없었다고 판단할 수 없습니다."}) from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)



@app.post("/api/practice/P04/provision")
async def provision_p04_baseline(
    request: Request,
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    if await request.body():
        raise HTTPException(status_code=422, detail="provisioning inputs are server-owned")
    session_id = session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(status_code=409, detail="this session already has a running request")
    ACTIVE_SESSIONS.add(session_id)
    operation_id = str(uuid.uuid4())
    session[1]["resource_operation"] = {"problem": 'P04', "operation_id": operation_id}
    try:
        async with httpx.AsyncClient(timeout=480, follow_redirects=False, trust_env=False) as client:
            response = await client.post(
                f"{GATEWAY_URL}/v1/p04/resources/prepare", json={"operation_id": operation_id},
                headers={"Authorization": f"Bearer {H04_PROVISION_TOKEN}"},
            )
        result = response.json()
        if (response.status_code != 200 or result.get("practice_id") != "P04"
                or result.get("operation_id") != operation_id or result.get("state") != "ready"
                or not isinstance(result.get("resources"), dict)
                or result["resources"].get("provider_mode") != "aws"
                or not isinstance(result.get("evidence"), dict)):
            raise ValueError("P04 preparation response mismatch")
        return {"activity_id": "P04", "operation_id": operation_id, "resource_ready": True, "resource_progress": completed_resource_progress("P04", operation_id, "prepare"),
                "task_completed": False, "preparation": result,
                "next_check": "P04 전용 출력 이메일 정책이 준비됐습니다. 함수를 작성·빌드한 뒤 구현 검증을 실행하세요. 자원 준비는 과제 통과가 아닙니다."}
    except (httpx.RequestError, ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(status_code=502, detail={"task_completed": False, "security_verdict": "ERR",
            "course_verdict": "ERR", "activity_id": "P04", "operation_id": operation_id,
            "next_check": "P04 준비 기록과 AWS 자원 상태를 확인하세요. 오류가 나도 일부 Guardrail 자원이 남아 있을 수 있습니다."}) from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.get("/api/test-progress/P04")
async def p04_case_progress(session: tuple[str, dict] = Depends(require_session)):
    return session[1].get("p04_case_progress",{"suite_id":None,"cases":[],"phase":"idle","total":27})


@app.post("/api/practice/P04/verify")
async def verify_p04_guardrail_app(request: Request, session: tuple[str, dict] = Depends(require_csrf)):
    if await request.body():
        raise HTTPException(422,"verification inputs are server-owned")
    session_id=session[0]
    if session_id in ACTIVE_SESSIONS:
        raise HTTPException(409,"다른 질문·자원·채점 작업이 진행 중입니다.")
    ACTIVE_SESSIONS.add(session_id)
    suite=str(uuid.uuid4())
    progress={"suite_id":suite,"cases":[],"current_case":None,"phase":"running","total":27}
    session[1]["p04_case_progress"]=progress
    finished=False; definitions=[]
    def failure(reason):
        skipped=[{"case_id":case["case_id"],"status":"미실행","reason":"앞 케이스 실패로 중단"}
                 for case in definitions[len(progress["cases"]):]]
        return {"activity_id":"P04","execution_id":suite,"task_completed":False,
                "security_verdict":"ERR","course_verdict":"ERR","verified_by":"guided-evidence-verifier",
                "contract_version":"p04-guardrail-v1","reason":reason,
                "next_check":"실패한 케이스의 상세 결과를 확인하고 코드를 수정한 뒤 다시 채점하세요.",
                "result":{"cases":[*progress["cases"],*skipped]},"stopped_early":True}
    try:
        async with httpx.AsyncClient(timeout=210,follow_redirects=False,trust_env=False) as client:
            async def run(path,body):
                response=await client.post(f"{LAB04_URL}{path}",json=body,
                    headers={"Authorization":f"Bearer {LAB04_TOKEN}"})
                if response.status_code!=200 or response.json().get("suite_id")!=suite:
                    raise ValueError("P04 runner response mismatch")
                return response.json()
            started=await run("/v1/start",{"suite_id":suite})
            definitions=started["cases"]
            if not isinstance(definitions,list) or len(definitions)!=27:
                raise ValueError("P04 case mapping mismatch")
            for index,case in enumerate(definitions):
                progress["phase"]="running"
                progress["current_case"]={"case_id":case["case_id"],"status":"실행 중",
                    "started_at":datetime.now(timezone.utc).isoformat()}
                step=await run("/v1/step",{"suite_id":suite,"index":index})
                if step.get("index")!=index or step.get("case_id")!=case["case_id"]:
                    raise ValueError("P04 case identity mismatch")
                progress["phase"]="verifying";progress["current_case"]["status"]="채점 중"
                checked=await client.post(f"{VERIFIER_URL}/v1/verify/p04-case",json={"suite_id":suite,"index":index},
                    headers={"Authorization":f"Bearer {VERIFIER_TOKEN}"})
                if checked.status_code!=200:
                    raise ValueError("P04 case verifier unavailable")
                outcome=checked.json()
                if (outcome.get("suite_id")!=suite or outcome.get("index")!=index
                    or outcome.get("case_id")!=case["case_id"] or outcome.get("status") not in {"PASS","ERR"}
                    or outcome.get("case_verified") is not (outcome["status"]=="PASS")):
                    raise ValueError("P04 case verdict mismatch")
                progress["cases"].append(outcome);progress["current_case"]=None
                if outcome["status"]!="PASS":
                    await run("/v1/finish",{"suite_id":suite,"stopped":True});finished=True
                    progress["verdict"]="ERR"
                    return failure(f"케이스 {index+1} ({case['case_id']})에서 실패해 뒤 테스트를 중단했습니다.")
            await run("/v1/finish",{"suite_id":suite,"stopped":False});finished=True
            progress["phase"]="verifying"
            response=await client.post(f"{VERIFIER_URL}/v1/verify/p04",json={"suite_id":suite},
                headers={"Authorization":f"Bearer {VERIFIER_TOKEN}"})
            if response.status_code!=200:
                raise ValueError("P04 final verifier unavailable")
            result=response.json()
            if (result.get("activity_id")!="P04" or result.get("execution_id")!=suite
                or result.get("verified_by")!="guided-evidence-verifier"
                or result.get("contract_version")!="p04-guardrail-v1"
                or result.get("course_verdict")!=result.get("security_verdict")
                or result.get("security_verdict") not in {"PASS","ERR"}
                or type(result.get("task_completed")) is not bool
                or result["task_completed"]!=(result["security_verdict"]=="PASS")):
                raise ValueError("P04 final result mismatch")
            progress["verdict"]=result["security_verdict"]
            return result
    except (httpx.HTTPError,ValueError,KeyError,TypeError,AttributeError):
        current=progress["current_case"]
        if current:
            progress["cases"].append({"case_id":current["case_id"],"status":"ERR","case_verified":False,
                "reason":"실행 또는 독립 검증 응답을 받지 못했습니다."})
        progress["verdict"]="ERR"
        raise HTTPException(502,detail=failure("실행 또는 검증 오류로 뒤 테스트를 중단했습니다.")) from None
    finally:
        if not finished:
            try:
                async with httpx.AsyncClient(timeout=5,trust_env=False) as client:
                    await client.post(f"{LAB04_URL}/v1/finish",json={"suite_id":suite,"stopped":True},
                        headers={"Authorization":f"Bearer {LAB04_TOKEN}"})
            except httpx.HTTPError:
                pass
        progress["phase"]="finished";progress["current_case"]=None
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H04/provision")
@app.post("/api/hands-on/H04/verify")
async def retired_h04_action(
    session: tuple[str, dict] = Depends(require_csrf),
) -> dict:
    raise HTTPException(status_code=410, detail="H04 retired; use /api/practice/P04")


@app.post("/api/hands-on/H05/verify")
@app.post("/api/practice/P05/verify")
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
    case_order=("contact-exact","contact-paraphrase","recovery-risk","unsupported")
    progress=session[1].get("native_progress")
    if progress:progress.update(suite_id=suite_id,total=len(case_order))
    checks=[]
    cases = []
    experience_cases = []
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
                response = await native_post(client,
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
                experience_cases.append(response.json())
                cases.append(
                    {
                        "case_id": case_id,
                        "execution_id": execution_id,
                        "started_at": case_started_at,
                    }
                )

                if not EXPLORATION.get():
                    checked=await native_post(client,f"{VERIFIER_URL}/v1/verify/lab-05-case",
                        json={"suite_id":suite_id,"started_at":started_at,"cases":[cases[-1]]},headers={"Authorization":f"Bearer {VERIFIER_TOKEN}"})
                    outcome=checked.json() if checked.status_code==200 else {"status":"ERR","case_verified":False,"reason":"케이스 검증기에 연결하지 못했습니다."}
                    passed=outcome.get("case_id")==case_id and outcome.get("case_verified") is True and outcome.get("status")=="PASS"
                    status="PASS" if passed else "HIT" if outcome.get("status")=="HIT" else "ERR"
                    receipt_cases=outcome.get("result",{}).get("cases",[])
                    native_case=receipt_cases[0] if receipt_cases and isinstance(receipt_cases[0],dict) else {}
                    check={**native_case,"case_id":case_id,"status":status,"case_verified":passed,"reason":outcome.get("reason"),"evidence":outcome.get("evidence",[])}
                    checks.append(check)
                    if progress:
                        progress["cases"][-1].update(check);progress["total"]=len(case_order)
                    if not passed:
                        skipped=[{"case_id":later,"status":"미실행","reason":"앞 케이스 실패로 중단"} for later in case_order[len(checks):]]
                        if progress:progress["cases"].extend(skipped)
                        return {"activity_id":"H05","execution_id":suite_id,"started_at":started_at,"course_verdict":status,"task_completed":False,
                            "verified_by":"guided-evidence-verifier","reason":outcome.get("reason"),
                            "result":{"cases":checks+skipped,"source_digest":outcome.get("source_digest"),"evaluation":None},
                            "stage_calls":[{"stage":"learner_nemo_dialog","attempted":True,"outcome":"stopped-after-case-check"},
                                {"stage":"nemo_topical_evaluation","attempted":False,"outcome":"not-run"}]}

            evaluation = await native_post(client,
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

            if EXPLORATION.get():
                return await exploration_result({"cases": experience_cases, "evaluation": evaluation.json()})
            verified = await native_post(client,
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
        payload=verified.json()
        if isinstance(payload.get("result",{}).get("cases"),list):
            by_case={check["case_id"]:check for check in checks}
            payload["result"]["cases"]=[{**row,**{key:by_case[row["case_id"]][key] for key in ("status","case_verified","reason")}}
                if row.get("case_id") in by_case else row for row in payload["result"]["cases"]]
        return payload
    except (httpx.RequestError, HTTPException, ValueError, KeyError, TypeError):
        if EXPLORATION.get():
            raise HTTPException(status_code=502, detail="현재 Dialog 실행과 서비스 상태를 확인하세요.") from None
        failed = case_order[len(checks)] if len(checks) < len(case_order) else "topical-evaluation"
        rows = checks + [{"case_id":failed,"status":"ERR","case_verified":False,
                          "reason":"실행 또는 독립 검증 응답이 완료되지 않았습니다."}]
        rows.extend({"case_id":later,"status":"미실행","reason":"앞 케이스 오류로 중단"}
                    for later in case_order[len(checks)+1:])
        if progress:progress.update(cases=rows,total=len(rows),current_case=None)
        return {"activity_id":"H05","execution_id":suite_id,"started_at":started_at,
                "course_verdict":"ERR","task_completed":False,"result":{"cases":rows},
                "reason":"Dialog 실행 또는 평가가 끝나지 않았습니다. 해당 서비스 상태를 확인하세요.",
                "stage_calls":[]}
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H06/verify")
@app.post("/api/practice/P06/verify")
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
            prepared = await native_post(client,
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
            if EXPLORATION.get():
                executed = await native_post(client,
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
                if EXPLORATION.get():
                    return await exploration_result(executed.json())
            progress=session[1].get("native_progress")
            checks=[]
            if progress:progress.update(suite_id=suite_id,total=len(case_ids))
            for case_id in case_ids:
                if progress:
                    progress.update(phase="running",current_case={"case_id":case_id,"status":"실행 중","started_at":datetime.now(timezone.utc).isoformat()})
                try:
                    executed=await client.post(f"{LAB06_URL}/v1/run-case",json={"suite_id":suite_id,"started_at":started_at,"cases":learner_cases,"case_id":case_id},headers={"Authorization":f"Bearer {LAB06_TOKEN}"})
                    if executed.status_code!=200:
                        outcome={"status":"ERR","case_verified":False,"reason":"Action 케이스 실행이 완료되지 않았습니다."}
                    else:
                        checked=await client.post(f"{VERIFIER_URL}/v1/verify/h06-case",json={"suite_id":suite_id,"started_at":started_at,"case_id":case_id},headers={"Authorization":f"Bearer {VERIFIER_TOKEN}"})
                        outcome=checked.json() if checked.status_code==200 else {"status":"ERR","case_verified":False,"reason":"케이스 검증기에 연결하지 못했습니다."}
                except (httpx.RequestError,ValueError):
                    outcome={"status":"ERR","case_verified":False,"reason":"실행 또는 검증 응답을 수집하지 못했습니다. 해당 서비스의 로그를 확인하세요."}
                passed=outcome.get("case_id")==case_id and outcome.get("case_verified") is True and outcome.get("status")=="PASS"
                status="PASS" if passed else "HIT" if outcome.get("status")=="HIT" else "ERR"
                rows=outcome.get("result",{}).get("cases",[])
                row=rows[0] if rows else {}
                checks.append({**row,"case_id":case_id,"status":status,"case_verified":passed,"reason":outcome.get("reason")})
                if progress:progress.update(cases=list(checks),current_case=None)
                if not passed:
                    skipped=[{"case_id":later,"status":"미실행","reason":"앞 케이스 실패로 중단"} for later in case_ids[len(checks):]]
                    if progress:progress["cases"].extend(skipped)
                    return {"activity_id":"H06","execution_id":suite_id,"started_at":started_at,"course_verdict":status,"task_completed":False,
                        "verified_by":outcome.get("verified_by","guided-control-center"),"reason":outcome.get("reason"),"stage_calls":[{"stage":"learner_nemo_action","attempted":True,"outcome":"stopped-after-case-check"}]+([{ "stage":"action_policy","attempted":True,"outcome":status}] if row.get("raw_action_events") else []),"result":{**outcome.get("result",{}),"cases":checks+skipped,"source_digest":outcome.get("source_digest")}}
            verified = await native_post(client,
                f"{VERIFIER_URL}/v1/verify/h06",
                json={
                    "suite_id": suite_id,
                    "started_at": started_at,
                },
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        payload=verified.json()
        by_case={check["case_id"]:check for check in checks}
        if isinstance(payload.get("result",{}).get("cases"),list):
            payload["result"]["cases"]=[{**row,**{key:by_case[row["case_id"]][key] for key in ("status","case_verified","reason")}}
                if row.get("case_id") in by_case else row for row in payload["result"]["cases"]]
        return payload
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="internal guided service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


async def close_h07_gateway_suite(suite_id: str) -> bool:
    """Close unused one-time grants even when the learner path fails."""
    try:
        async with httpx.AsyncClient(timeout=H07_CLOSE_TIMEOUT) as client:
            for attempt in range(3):
                response = await native_post(client,
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


async def close_h08_gateway_suite(suite_id: str) -> bool:
    """Close every unused H08 role grant before read-only verification."""
    try:
        async with httpx.AsyncClient(timeout=H07_CLOSE_TIMEOUT) as client:
            for attempt in range(3):
                response = await native_post(client,
                    f"{GATEWAY_URL}/v1/h08/suites/{suite_id}/close",
                    headers={"Authorization": f"Bearer {H08_GATEWAY_CONTROL_TOKEN}"},
                )
                if response.status_code == 200:
                    return response.json().get("suite_id") == suite_id
                if response.status_code != 409:
                    return False
                await asyncio.sleep(0.2 * (attempt + 1))
        return False
    except (httpx.RequestError, ValueError):
        return False


async def close_h09_sink_suite(suite_id: str) -> bool:
    """Close every unused H09 delivery grant before read-only verification."""
    try:
        async with httpx.AsyncClient(timeout=H07_CLOSE_TIMEOUT) as client:
            response = await native_post(client,
                f"{H09_SINK_URL}/v1/suites/{suite_id}/close",
                headers={"Authorization": f"Bearer {H09_SINK_CONTROL_TOKEN}"},
            )
        return response.status_code == 200 and response.json().get("suite_id") == suite_id
    except (httpx.RequestError, ValueError):
        return False


@app.post("/api/hands-on/H07/verify")
@app.post("/api/practice/P07/verify")
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
            prepared = await native_post(client,
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
            checks = []
            if EXPLORATION.get():
                executed = await native_post(client,
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
                            "next_check": "H07 image, NeMo 0.24.1 설정과 입력 Rail 문법을 확인합니다.",
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
                return await exploration_result(executed.json())
            progress = session[1].get("native_progress")
            if progress: progress.update(suite_id=suite_id,total=len(expected_order))
            for case_id in expected_order:
                if progress: progress.update(phase="running",current_case={"case_id":case_id,"status":"실행 중","started_at":datetime.now(timezone.utc).isoformat()})
                try:
                    executed = await native_post(client,f"{LAB07_URL}/v1/run-case",json={"suite_id":suite_id,"started_at":started_at,"cases":learner_cases,"case_id":case_id},headers={"Authorization":f"Bearer {LAB07_TOKEN}"})
                    if executed.status_code != 200 or executed.json().get("suite_id") != suite_id:
                        outcome = {"course_verdict":"ERR","reason":"Self-check 케이스 실행이 완료되지 않았습니다."}
                    else:
                        closed = await client.post(f"{GATEWAY_URL}/v1/h07/suites/{suite_id}/cases/{case_id}/close",headers={"Authorization":f"Bearer {H07_GATEWAY_CONTROL_TOKEN}"})
                        if closed.status_code != 200 or closed.json().get("case_id") != case_id or closed.json().get("suite_id") != suite_id:
                            outcome = {"course_verdict":"ERR","reason":"현재 케이스의 모델 호출 권한을 종료하지 못했습니다."}
                        else:
                            if progress: progress["phase"] = "verifying"
                            checked = await client.post(f"{VERIFIER_URL}/v1/verify/h07-case",json={"suite_id":suite_id,"started_at":started_at,"case_id":case_id},headers={"Authorization":f"Bearer {VERIFIER_TOKEN}"})
                            outcome = checked.json() if checked.status_code == 200 else {"course_verdict":"ERR","reason":"Self-check 독립 검증기에 연결하지 못했습니다."}
                except (httpx.RequestError,ValueError):
                    outcome = {"course_verdict":"ERR","reason":"Self-check 실행·권한 종료·검증 응답을 수집하지 못했습니다."}
                passed = outcome.get("case_id") == case_id and outcome.get("case_verified") is True and outcome.get("status") == "PASS"
                status = "PASS" if passed else "HIT" if outcome.get("course_verdict") == "HIT" else "ERR"
                row = next((row for row in outcome.get("result",{}).get("cases",[]) if row.get("case_id") == case_id),{})
                checks.append({**row,"case_id":case_id,"status":status,"case_verified":passed,"reason":outcome.get("reason")})
                if progress: progress.update(cases=list(checks),current_case=None)
                if not passed:
                    skipped = [{"case_id":later,"status":"미실행","reason":"앞 케이스 실패로 중단"} for later in expected_order[len(checks):]]
                    if progress: progress["cases"].extend(skipped)
                    suite_closed = await close_h07_gateway_suite(suite_id)
                    if not suite_closed:
                        outcome = {**outcome,"course_verdict":"ERR","reason":"호출 권한 종료 실패"}
                        outcome["reason"] = "사용하지 않은 모델 호출 권한의 종료를 확인하지 못했습니다. Gateway 로그를 확인하세요."
                        status = "ERR"
                    return {**outcome,"activity_id":"H07","execution_id":suite_id,"started_at":started_at,"course_verdict":status,"task_completed":False,"result":{**outcome.get("result",{}),"cases":checks+skipped}}
            suite_closed = await close_h07_gateway_suite(suite_id)
            if not suite_closed:
                raise HTTPException(502,detail={"course_verdict":"ERR","downstream_called":True,"next_check":"H07 Gateway 로그와 진행 중인 호출을 확인하세요."})
            verified = await native_post(client,
                f"{VERIFIER_URL}/v1/verify/h07",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        payload = verified.json()
        by_case = {row["case_id"]:row for row in checks}
        if isinstance(payload.get("result",{}).get("cases"),list):
            payload["result"]["cases"] = [{**row,**{key:by_case[row["case_id"]][key] for key in ("status","case_verified","reason")}} for row in payload["result"]["cases"]]
        return payload
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


@app.post("/api/hands-on/H08/verify")
@app.post("/api/practice/P08/verify")
async def verify_h08_self_check_input(
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
            prepared = await native_post(client,
                f"{GATEWAY_URL}/v1/h08/suites",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {H08_GATEWAY_CONTROL_TOKEN}"},
            )
            if prepared.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "control_center",
                        "stopped_stage": "h08_gateway_prepare",
                        "downstream_called": False,
                        "course_verdict": "ERR",
                        "next_check": "H08 Gateway가 네 요청과 역할별 일회 capability를 만들었는지 확인합니다.",
                    },
                )
            provider_cases = prepared.json().get("cases")
            expected_order = [
                "normal-password-reset",
                "normal-report-injection",
                "risk-format-marker",
                "risk-admin-marker",
            ]
            if not isinstance(provider_cases, list) or [
                item.get("case_id") for item in provider_cases
            ] != expected_order:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "h08_gateway_prepare",
                        "stopped_stage": "h08_capability_contract",
                        "downstream_called": True,
                        "course_verdict": "ERR",
                        "next_check": "H08 Gateway가 정상 두 건과 위험 두 건을 고정 순서로 만들었는지 확인합니다.",
                    },
                )
            learner_cases = []
            for item in provider_cases:
                roles = item.get("roles")
                if not isinstance(roles, dict) or set(roles) != {"self_check_input", "main"}:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "successful_stage": "h08_gateway_prepare",
                            "stopped_stage": "h08_capability_contract",
                            "downstream_called": True,
                            "course_verdict": "ERR",
                            "next_check": "각 H08 Testcase에 Self-check와 Main 역할 capability가 있는지 확인합니다.",
                        },
                    )
                learner_cases.append(
                    {
                        "case_id": item["case_id"],
                        "execution_id": item["execution_id"],
                        "self_check_input_capability": roles["self_check_input"]["capability"],
                        "main_capability": roles["main"]["capability"],
                    }
                )
            checks = []
            if EXPLORATION.get():
                executed = await native_post(client,
                    f"{LAB08_URL}/v1/run",
                    json={"suite_id": suite_id, "started_at": started_at, "cases": learner_cases},
                    headers={"Authorization": f"Bearer {LAB08_TOKEN}"},
                )
                if executed.status_code != 200:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "successful_stage": "h08_gateway_prepare",
                            "stopped_stage": "guided_h08_self_check_input",
                            "downstream_called": True,
                            "course_verdict": "ERR",
                            "next_check": "H08 image, NeMo 0.24.1 설정과 self check input Prompt를 확인합니다.",
                        },
                    )
                if executed.json().get("suite_id") != suite_id:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "successful_stage": "guided_h08_self_check_input",
                            "stopped_stage": "h08_learner_receipt",
                            "downstream_called": True,
                            "course_verdict": "ERR",
                            "next_check": "H08 learner가 현재 suite ID의 실행 영수증을 저장했는지 확인합니다.",
                        },
                    )
                suite_closed = await close_h08_gateway_suite(suite_id)
                if not suite_closed:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "successful_stage": "guided_h08_self_check_input",
                            "stopped_stage": "h08_gateway_close",
                            "downstream_called": True,
                            "course_verdict": "ERR",
                            "next_check": "실행 중인 H08 역할 호출이 끝났고 사용하지 않은 capability가 닫혔는지 확인합니다.",
                        },
                    )
                return await exploration_result(executed.json())
            progress = session[1].get("native_progress")
            if progress: progress.update(suite_id=suite_id,total=len(expected_order))
            for case_id in expected_order:
                if progress: progress.update(phase="running",current_case={"case_id":case_id,"status":"실행 중","started_at":datetime.now(timezone.utc).isoformat()})
                try:
                    executed = await native_post(client,f"{LAB08_URL}/v1/run-case",json={"suite_id":suite_id,"started_at":started_at,"cases":learner_cases,"case_id":case_id},headers={"Authorization":f"Bearer {LAB08_TOKEN}"})
                    if executed.status_code != 200 or executed.json().get("suite_id") != suite_id:
                        outcome = {"course_verdict":"ERR","reason":"Self-check 케이스 실행이 완료되지 않았습니다."}
                    else:
                        closed = await client.post(f"{GATEWAY_URL}/v1/h08/suites/{suite_id}/cases/{case_id}/close",headers={"Authorization":f"Bearer {H08_GATEWAY_CONTROL_TOKEN}"})
                        if closed.status_code != 200 or closed.json().get("case_id") != case_id or closed.json().get("suite_id") != suite_id:
                            outcome = {"course_verdict":"ERR","reason":"현재 케이스의 모델 호출 권한을 종료하지 못했습니다."}
                        else:
                            if progress: progress["phase"] = "verifying"
                            checked = await client.post(f"{VERIFIER_URL}/v1/verify/h08-case",json={"suite_id":suite_id,"started_at":started_at,"case_id":case_id},headers={"Authorization":f"Bearer {VERIFIER_TOKEN}"})
                            outcome = checked.json() if checked.status_code == 200 else {"course_verdict":"ERR","reason":"Self-check 독립 검증기에 연결하지 못했습니다."}
                except (httpx.RequestError,ValueError):
                    outcome = {"course_verdict":"ERR","reason":"Self-check 실행·권한 종료·검증 응답을 수집하지 못했습니다."}
                passed = outcome.get("case_id") == case_id and outcome.get("case_verified") is True and outcome.get("status") == "PASS"
                status = "PASS" if passed else "HIT" if outcome.get("course_verdict") == "HIT" else "ERR"
                row = next((row for row in outcome.get("result",{}).get("cases",[]) if row.get("case_id") == case_id),{})
                checks.append({**row,"case_id":case_id,"status":status,"case_verified":passed,"reason":outcome.get("reason")})
                if progress: progress.update(cases=list(checks),current_case=None)
                if not passed:
                    skipped = [{"case_id":later,"status":"미실행","reason":"앞 케이스 실패로 중단"} for later in expected_order[len(checks):]]
                    if progress: progress["cases"].extend(skipped)
                    suite_closed = await close_h08_gateway_suite(suite_id)
                    if not suite_closed:
                        outcome = {**outcome,"course_verdict":"ERR","reason":"호출 권한 종료 실패"}
                        outcome["reason"] = "사용하지 않은 모델 호출 권한의 종료를 확인하지 못했습니다. Gateway 로그를 확인하세요."
                        status = "ERR"
                    return {**outcome,"activity_id":"H08","execution_id":suite_id,"started_at":started_at,"course_verdict":status,"task_completed":False,"result":{**outcome.get("result",{}),"cases":checks+skipped}}
            suite_closed = await close_h08_gateway_suite(suite_id)
            if not suite_closed:
                raise HTTPException(502,detail={"course_verdict":"ERR","downstream_called":True,"next_check":"H08 Gateway 로그와 진행 중인 호출을 확인하세요."})
            verified = await native_post(client,
                f"{VERIFIER_URL}/v1/verify/h08",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        payload = verified.json()
        by_case = {row["case_id"]:row for row in checks}
        if isinstance(payload.get("result",{}).get("cases"),list):
            payload["result"]["cases"] = [{**row,**{key:by_case[row["case_id"]][key] for key in ("status","case_verified","reason")}} for row in payload["result"]["cases"]]
        return payload
    except HTTPException:
        if prepare_attempted and not suite_closed:
            await close_h08_gateway_suite(suite_id)
        raise
    except httpx.RequestError as exc:
        if prepare_attempted and not suite_closed:
            await close_h08_gateway_suite(suite_id)
        raise HTTPException(
            status_code=502,
            detail={
                "successful_stage": "control_center",
                "stopped_stage": "h08_internal_service",
                "downstream_called": prepare_attempted,
                "course_verdict": "ERR",
                "next_check": "H08 Gateway·learner 상태와 suite가 닫혔는지 확인합니다.",
            },
        ) from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H09/verify")
@app.post("/api/practice/P09/verify")
async def verify_h09_presidio_delivery(
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
    case_ids = ("clean", "input-email", "input-kr-rrn", "output-email")
    executions = [
        {"case_id": case_id, "execution_id": str(uuid.uuid4())}
        for case_id in case_ids
    ]
    prepare_attempted = False
    suite_closed = False
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            prepare_attempted = True
            prepared = await native_post(client,
                f"{H09_SINK_URL}/v1/suites",
                json={
                    "suite_id": suite_id,
                    "started_at": started_at,
                    "executions": executions,
                },
                headers={"Authorization": f"Bearer {H09_SINK_CONTROL_TOKEN}"},
            )
            grants = prepared.json().get("cases") if prepared.status_code == 200 else None
            if not isinstance(grants, list) or [
                item.get("case_id") for item in grants
            ] != list(case_ids):
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "control_center",
                        "stopped_stage": "h09_delivery_prepare",
                        "downstream_called": False,
                        "course_verdict": "ERR",
                        "next_check": "H09 Delivery Sink가 네 고정 Case의 일회 capability를 만들었는지 확인합니다.",
                    },
                )
            learner_cases = [
                {
                    "case_id": item["case_id"],
                    "execution_id": item["execution_id"],
                    "capability": item["capability"],
                }
                for item in grants
            ]
            checks = []
            if EXPLORATION.get():
                executed = await native_post(client,
                    f"{LAB09_URL}/v1/run",
                    json={
                        "suite_id": suite_id,
                        "started_at": started_at,
                        "cases": learner_cases,
                    },
                    headers={"Authorization": f"Bearer {LAB09_TOKEN}"},
                )
                if executed.status_code != 200 or executed.json().get("suite_id") != suite_id:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "successful_stage": "h09_delivery_prepare",
                            "stopped_stage": "guided_h09_presidio",
                            "downstream_called": True,
                            "course_verdict": "ERR",
                            "next_check": "H09 image와 policy.py의 Presidio 실행·전달 계약을 확인합니다.",
                        },
                    )
                suite_closed = await close_h09_sink_suite(suite_id)
                if not suite_closed:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "successful_stage": "guided_h09_presidio",
                            "stopped_stage": "h09_delivery_close",
                            "downstream_called": True,
                            "course_verdict": "ERR",
                            "next_check": "H09 전달이 끝났고 Sink의 일회 capability가 닫혔는지 확인합니다.",
                        },
                    )
                return await exploration_result(executed.json())
            progress = session[1].get("native_progress")
            if progress: progress.update(suite_id=suite_id,total=len(case_ids))
            for case_id in case_ids:
                if progress: progress.update(phase="running",current_case={"case_id":case_id,"status":"실행 중","started_at":datetime.now(timezone.utc).isoformat()})
                try:
                    executed = await client.post(f"{LAB09_URL}/v1/run-case",json={"suite_id":suite_id,"started_at":started_at,"cases":learner_cases,"case_id":case_id},headers={"Authorization":f"Bearer {LAB09_TOKEN}"})
                    if executed.status_code != 200 or executed.json().get("suite_id") != suite_id:
                        outcome = {"course_verdict":"ERR","reason":"Presidio 케이스 실행이 완료되지 않았습니다."}
                    else:
                        closed = await client.post(f"{H09_SINK_URL}/v1/suites/{suite_id}/cases/{case_id}/close",headers={"Authorization":f"Bearer {H09_SINK_CONTROL_TOKEN}"})
                        if closed.status_code != 200 or closed.json().get("case_id") != case_id or closed.json().get("suite_id") != suite_id:
                            outcome = {"course_verdict":"ERR","reason":"현재 케이스의 전달 권한을 종료하지 못했습니다."}
                        else:
                            if progress: progress["phase"] = "verifying"
                            checked = await client.post(f"{VERIFIER_URL}/v1/verify/h09-case",json={"suite_id":suite_id,"started_at":started_at,"case_id":case_id},headers={"Authorization":f"Bearer {VERIFIER_TOKEN}"})
                            outcome = checked.json() if checked.status_code == 200 else {"course_verdict":"ERR","reason":"Presidio 독립 검증기에 연결하지 못했습니다."}
                except (httpx.RequestError,ValueError):
                    outcome = {"course_verdict":"ERR","reason":"Presidio 실행·권한 종료·검증 응답을 수집하지 못했습니다."}
                passed = outcome.get("case_id") == case_id and outcome.get("case_verified") is True and outcome.get("status") == "PASS"
                status = "PASS" if passed else "HIT" if outcome.get("course_verdict") == "HIT" else "ERR"
                row = next((row for row in outcome.get("result",{}).get("cases",[]) if row.get("case_id") == case_id),{})
                checks.append({**row,"case_id":case_id,"status":status,"case_verified":passed,"reason":outcome.get("reason")})
                if progress: progress.update(cases=list(checks),current_case=None)
                if not passed:
                    skipped = [{"case_id":later,"status":"미실행","reason":"앞 케이스 실패로 중단"} for later in case_ids[len(checks):]]
                    if progress: progress["cases"].extend(skipped)
                    suite_closed = await close_h09_sink_suite(suite_id)
                    if not suite_closed:
                        outcome = {**outcome,"course_verdict":"ERR","reason":"호출 권한 종료 실패"}
                        outcome["reason"] = "사용하지 않은 전달 권한의 종료를 확인하지 못했습니다. Delivery Sink 로그를 확인하세요."
                        status = "ERR"
                    return {**outcome,"activity_id":"H09","execution_id":suite_id,"started_at":started_at,"course_verdict":status,"task_completed":False,"result":{**outcome.get("result",{}),"cases":checks+skipped}}
            suite_closed = await close_h09_sink_suite(suite_id)
            if not suite_closed:
                raise HTTPException(502,detail={"course_verdict":"ERR","downstream_called":True,"next_check":"H09 Delivery Sink 로그와 전달 기록을 확인하세요."})
            verified = await native_post(client,
                f"{VERIFIER_URL}/v1/verify/h09",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        payload=verified.json()
        by_case={row["case_id"]:row for row in checks}
        if isinstance(payload.get("result",{}).get("cases"),list):
            payload["result"]["cases"]=[{**row,**{key:by_case[row["case_id"]][key] for key in ("status","case_verified","reason")}} for row in payload["result"]["cases"]]
        return payload
    except HTTPException:
        if prepare_attempted and not suite_closed:
            await close_h09_sink_suite(suite_id)
        raise
    except (httpx.RequestError, ValueError) as exc:
        if prepare_attempted and not suite_closed:
            await close_h09_sink_suite(suite_id)
        raise HTTPException(
            status_code=502,
            detail={
                "successful_stage": "control_center",
                "stopped_stage": "h09_internal_service",
                "downstream_called": prepare_attempted,
                "course_verdict": "ERR",
                "next_check": "H09 learner와 Delivery Sink 상태 및 닫힌 suite를 확인합니다.",
            },
        ) from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H10/verify")
@app.post("/api/practice/P10/verify")
async def verify_h10_output_rail(
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
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            checks=[]
            execution_ids=[str(uuid.uuid4()) for _ in range(4)]
            case_ids=["normal-reset-guide","normal-report-secret","risk-recovery-code","risk-internal-note"]
            if EXPLORATION.get():
                executed = await native_post(client,
                    f"{LAB10_URL}/v1/run",
                    json={
                        "suite_id": suite_id,
                        "started_at": started_at,
                        "execution_ids": [str(uuid.uuid4()) for _ in range(4)],
                    },
                    headers={"Authorization": f"Bearer {LAB10_TOKEN}"},
                )
                if executed.status_code != 200 or executed.json().get("suite_id") != suite_id:
                    raise HTTPException(
                        status_code=502,
                        detail={
                            "successful_stage": "control_center",
                            "stopped_stage": "guided_h10_output_rail",
                            "downstream_called": True,
                            "course_verdict": "ERR",
                            "next_check": "H10 NeMo config와 Output Rail Prompt 문법을 확인합니다.",
                        },
                    )
                return await exploration_result(executed.json())
            progress=session[1].get("native_progress")
            if progress:progress.update(suite_id=suite_id,total=len(case_ids))
            for case_id in case_ids:
                if progress:progress.update(phase="running",current_case={"case_id":case_id,"status":"실행 중","started_at":datetime.now(timezone.utc).isoformat()})
                try:
                    executed=await client.post(f"{LAB10_URL}/v1/run-case",json={"suite_id":suite_id,"started_at":started_at,"execution_ids":execution_ids,"case_id":case_id},headers={"Authorization":f"Bearer {LAB10_TOKEN}"})
                    if executed.status_code!=200 or executed.json().get("suite_id")!=suite_id:
                        outcome={"course_verdict":"ERR","reason":"출력 검사 케이스가 완료되지 않았습니다."}
                    else:
                        if progress:progress["phase"]="verifying"
                        checked=await client.post(f"{VERIFIER_URL}/v1/verify/h10-case",json={"suite_id":suite_id,"started_at":started_at,"case_id":case_id},headers={"Authorization":f"Bearer {VERIFIER_TOKEN}"})
                        outcome=checked.json() if checked.status_code==200 else {"course_verdict":"ERR","reason":"출력 검사 증거를 대조하지 못했습니다."}
                except (httpx.RequestError,ValueError):outcome={"course_verdict":"ERR","reason":"출력 검사 실행·검증 응답을 수집하지 못했습니다."}
                passed=outcome.get("case_id")==case_id and outcome.get("case_verified") is True and outcome.get("status")=="PASS"
                status="PASS" if passed else "HIT" if outcome.get("course_verdict")=="HIT" else "ERR"
                row=next((row for row in outcome.get("result",{}).get("cases",[]) if row.get("case_id")==case_id),{})
                checks.append({**row,"case_id":case_id,"status":status,"case_verified":passed,"reason":outcome.get("reason")})
                if progress:progress.update(cases=list(checks),current_case=None)
                if not passed:
                    skipped=[{"case_id":later,"status":"미실행","reason":"앞 케이스 실패로 중단"} for later in case_ids[len(checks):]]
                    if progress:progress["cases"].extend(skipped)
                    return {**outcome,"activity_id":"H10","execution_id":suite_id,"started_at":started_at,"course_verdict":status,"task_completed":False,"result":{**outcome.get("result",{}),"cases":checks+skipped}}
            verified = await native_post(client,
                f"{VERIFIER_URL}/v1/verify/h10",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        payload=verified.json();by_case={row["case_id"]:row for row in checks}
        if isinstance(payload.get("result",{}).get("cases"),list):
            payload["result"]["cases"]=[{**row,**{key:by_case[row["case_id"]][key] for key in ("status","case_verified","reason")}} for row in payload["result"]["cases"]]
        return payload
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail={
                "successful_stage": "control_center",
                "stopped_stage": "h10_internal_service",
                "downstream_called": False,
                "course_verdict": "ERR",
                "next_check": "H10 learner·Gateway·verifier 상태를 확인합니다.",
            },
        ) from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H11/verify")
@app.post("/api/practice/P11/verify")
async def verify_h11_rag_provenance(
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
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            if EXPLORATION.get():
                executed = await native_post(client,
                    f"{LAB11_URL}/v1/run", json={"suite_id":suite_id,"started_at":started_at,"execution_id":str(uuid.uuid4())},
                    headers={"Authorization":f"Bearer {LAB11_TOKEN}"})
                if executed.status_code != 200:
                    raise HTTPException(502, "H11 direct execution unavailable")
                return await exploration_result(executed.json())
            case_ids = ["normal-approved", "client-self-approval", "client-tenant-spoof", "client-role-spoof"]
            execution_id = str(uuid.uuid4())
            progress = session[1].get("native_progress")
            checks = []
            if progress: progress.update(suite_id=suite_id, total=len(case_ids))
            for case_id in case_ids:
                if progress: progress.update(phase="running", current_case={"case_id":case_id,"status":"실행 중","started_at":datetime.now(timezone.utc).isoformat()})
                try:
                    executed = await client.post(f"{LAB11_URL}/v1/run-case", json={"suite_id":suite_id,"started_at":started_at,"execution_id":execution_id,"case_id":case_id}, headers={"Authorization":f"Bearer {LAB11_TOKEN}"})
                    if executed.status_code != 200 or executed.json().get("suite_id") != suite_id:
                        outcome = {"course_verdict":"ERR", "reason":"검색 케이스 실행이 완료되지 않았습니다."}
                    else:
                        if progress: progress["phase"] = "verifying"
                        verified_case = await client.post(f"{VERIFIER_URL}/v1/verify/h11-case", json={"suite_id":suite_id,"started_at":started_at,"case_id":case_id}, headers={"Authorization":f"Bearer {VERIFIER_TOKEN}"})
                        outcome = verified_case.json() if verified_case.status_code == 200 else {"course_verdict":"ERR","reason":"검색 증거 검증기에 연결하지 못했습니다."}
                except (httpx.RequestError, ValueError):
                    outcome = {"course_verdict":"ERR", "reason":"검색 또는 검증 응답을 수집하지 못했습니다."}
                passed = outcome.get("case_id") == case_id and outcome.get("case_verified") is True and outcome.get("status") == "PASS"
                status = "PASS" if passed else "HIT" if outcome.get("course_verdict") == "HIT" else "ERR"
                row = next((row for row in outcome.get("result", {}).get("cases", []) if row.get("case_id") == case_id), {})
                checks.append({**row,"case_id":case_id,"status":status,"case_verified":passed,"reason":outcome.get("reason")})
                if progress: progress.update(cases=list(checks), current_case=None)
                if not passed:
                    skipped = [{"case_id":later,"status":"미실행","reason":"앞 케이스 실패로 중단"} for later in case_ids[len(checks):]]
                    if progress: progress["cases"].extend(skipped)
                    return {**outcome,"activity_id":"H11","execution_id":suite_id,"started_at":started_at,"course_verdict":status,"task_completed":False,"result":{**outcome.get("result",{}),"cases":checks+skipped}}
            verified = await native_post(client,
                f"{VERIFIER_URL}/v1/verify/h11",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        payload = verified.json()
        by_case = {row["case_id"]:row for row in checks}
        if isinstance(payload.get("result", {}).get("cases"), list):
            payload["result"]["cases"] = [{**row, **{key:by_case[row["case_id"]][key] for key in ("status", "case_verified", "reason")}} for row in payload["result"]["cases"]]
        return payload
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="H11 internal service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)

async def p12_post_json(client, url, token, suite_id, deadline, case_id=None):
    state=NATIVE_SESSION.get()
    if state and url.endswith('/v1/run'):
        progress=state['native_progress'];progress['suite_id']=suite_id
        progress['current_case']={'case_id':'Application 요청 실행','status':'실행 중','started_at':datetime.now(timezone.utc).isoformat()}
        state['_native_target']={'url':url.rsplit('/v1/',1)[0]+'/v1/progress/'+suite_id,'headers':{'Authorization':'Bearer '+token}}
    elif state and '/v1/verify/' in url and case_id is None:
        state['native_progress']['phase']='verifying';state['native_progress']['current_case']=None
    async def receive():
        async with client.stream("POST", url, json={"suite_id": suite_id, **({"case_id": case_id} if case_id is not None else {})},
                headers={"Authorization": f"Bearer {token}", **({"X-Preview-Case":PREVIEW_CASE.get()} if PREVIEW_CASE.get() and url.endswith("/v1/run") else {})}) as response:
            if response.status_code != 200:
                raise ValueError("P12 service response unavailable")
            raw = bytearray()
            async for chunk in response.aiter_bytes():
                raw.extend(chunk)
                if len(raw) > 2097152:
                    raise ValueError("oversized P12 response")
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("invalid P12 response")
            return value
    return await asyncio.wait_for(receive(), timeout=deadline)


P12_CASE_IDS = ("normal", "input-pii", "invalid-credential", "no-scope", "input-block", "retrieval-block", "output-block", "no-hits")


@app.post("/api/hands-on/H12/verify")
@app.post("/api/practice/P12/verify")
async def verify_h12_application_pipeline(
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
    stopped = "p12_runner"
    cases = []
    state = NATIVE_SESSION.get()
    progress = state["native_progress"] if state else {}
    progress.update(total=len(P12_CASE_IDS), cases=cases, phase="running")
    current = P12_CASE_IDS[0]
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(770.0, connect=3.0),
                follow_redirects=False, trust_env=False) as client:
            if EXPLORATION.get():
                executed = await p12_post_json(client, f"{LAB12_URL}/v1/run", LAB12_TOKEN, suite_id, 780)
                if executed.get("suite_id") != suite_id:
                    raise ValueError("P12 execution identity mismatch")
                return await exploration_result(executed)
            for index, current in enumerate(P12_CASE_IDS):
                progress.update(phase="running", current_case={"case_id":current, "status":"실행 중",
                    "started_at":datetime.now(timezone.utc).isoformat()})
                executed = await p12_post_json(client, f"{LAB12_URL}/v1/run-case", LAB12_TOKEN, suite_id, 780, current)
                expected = "finished" if index == len(P12_CASE_IDS)-1 else "paused"
                if executed.get("suite_id") != suite_id or executed.get("run_state") not in {expected, "error"}:
                    raise ValueError("P12 execution identity or state mismatch")
                stopped = "p12_verifier"
                progress["phase"] = "verifying"
                progress["current_case"]["status"] = "독립 검증 중"
                checked = await p12_post_json(client, f"{VERIFIER_URL}/v1/verify/p12-case", VERIFIER_TOKEN, suite_id, 190, current)
                if (checked.get("activity_id") != "P12" or checked.get("execution_id") != suite_id
                        or checked.get("case_id") != current or checked.get("verified_by") != "guided-evidence-verifier"
                        or checked.get("course_verdict") not in {"PASS", "ERR"}
                        or checked.get("case_verified") is not (checked["course_verdict"] == "PASS")
                        or checked.get("task_completed") is not False
                        or (executed.get("run_state") == "error" and checked["course_verdict"] == "PASS")):
                    raise ValueError("P12 case verification mismatch")
                by_case = {row["case_id"]:row for row in checked["result"]["cases"]}
                row = by_case.get(current, {"case_id": current, "status":"ERR", "case_verified":False})
                if checked["course_verdict"] == "ERR":
                    row = {**row, "status":"ERR", "case_verified":False, "reason":checked["reason"]}
                elif row.get("status") != "PASS" or row.get("case_verified") is not True:
                    raise ValueError("P12 checked case missing")
                cases.append(row)
                progress["current_case"] = None
                if row["status"] != "PASS":
                    cases.extend({"case_id":name, "status":"미실행", "reason":"앞 케이스 실패로 중단"} for name in P12_CASE_IDS[index+1:])
                    checked["result"]["cases"] = cases
                    return checked
            stopped = "p12_verifier"
            verified = await p12_post_json(client, f"{VERIFIER_URL}/v1/verify/p12",
                                           VERIFIER_TOKEN, suite_id, 190)
        result = verified.get("result")
        if (verified.get("activity_id") != "P12" or verified.get("execution_id") != suite_id
                or type(verified.get("contract_version")) is not int or verified["contract_version"] != 2
                or verified.get("verified_by") != "guided-evidence-verifier"
                or not isinstance(result, dict) or result.get("suite_id") != suite_id
                or result.get("practice_id") != "P12" or result.get("execution_id") != "H12"
                or type(result.get("contract_version")) is not int or result["contract_version"] != 2
                or type(verified.get("task_completed")) is not bool
                or type(result.get("task_completed")) is not bool
                or verified["task_completed"] != result["task_completed"]
                or verified.get("security_verdict") not in {"PASS", "ERR"}
                or verified["security_verdict"] != result.get("security_verdict")
                or verified.get("course_verdict") != verified["security_verdict"]
                or verified["task_completed"] != (verified["security_verdict"] == "PASS")
                or (executed["run_state"] == "error" and verified["task_completed"])):
            raise ValueError("P12 verification identity or outcome mismatch")
        return verified
    except (httpx.HTTPError, ValueError, TimeoutError, KeyError, TypeError):
        if len(cases) < len(P12_CASE_IDS):
            cases.append({"case_id":current,"status":"ERR","reason":"현재 실행의 원문 기록을 확인하세요."})
            cases.extend({"case_id":name,"status":"미실행","reason":"앞 케이스 실패로 중단"} for name in P12_CASE_IDS[len(cases):])
        progress.update(phase="finished", current_case=None)
        return {
            "lab_id": "07-rag-boundary", "activity_id": "P12", "execution_id": suite_id,
            "contract_version": 2, "task_completed": False,
            "security_verdict": "ERR", "course_verdict": "ERR", "stage_calls": [],
            "stopped_stage": stopped, "downstream_called": None, "result":{"cases":cases},
            "reason": "P12 실행 또는 검증 응답을 확인하지 못했습니다. 뒤 서비스 호출 여부도 확정할 수 없습니다.",
            "next_check": "같은 실행 ID의 P12 원문 기록과 중단된 서비스의 로그를 확인하세요.",
        }
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/hands-on/H13/verify")
@app.post("/api/practice/P13/verify")
async def verify_h13_promptfoo(
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
    names = ("H13-NORMAL — 정상 요청은 Main 경로를 유지한다", "H13-RISK — 위험 요청은 Main 전에 멈춘다")
    cases = []
    state = NATIVE_SESSION.get()
    progress = state["native_progress"] if state else {}
    progress.update(total=len(names),cases=cases,phase="running")
    current = names[0]
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            headers = {"Authorization":f"Bearer {LAB13_TOKEN}"}
            verify_headers = {"Authorization":f"Bearer {VERIFIER_TOKEN}"}
            base = {"suite_id":suite_id,"started_at":started_at}
            if EXPLORATION.get():
                executed = await native_post(client, f"{LAB13_URL}/v1/run",json=base,headers=headers)
                if executed.status_code != 200: raise ValueError("Promptfoo execution unavailable")
                return await exploration_result(executed.json())
            for index,current in enumerate(names):
                progress.update(phase="running",current_case={"case_id":current,"status":"실행 중",
                    "started_at":datetime.now(timezone.utc).isoformat()})
                executed = await native_post(client,f"{LAB13_URL}/v1/run-case",json={**base,"case_id":current},headers=headers)
                if executed.status_code != 200: raise ValueError("Promptfoo execution unavailable")
                value = executed.json()
                if value.get("suite_id") != suite_id or value.get("case_id") != current: raise ValueError("Promptfoo execution mismatch")
                progress["phase"]="verifying";progress["current_case"]["status"]="독립 검증 중"
                checked = await native_post(client,f"{VERIFIER_URL}/v1/verify/h13-case",json={**base,"case_id":current},headers=verify_headers)
                if checked.status_code != 200: raise ValueError("Promptfoo verifier unavailable")
                payload = checked.json()
                if (payload.get("activity_id") != "H13" or payload.get("execution_id") != suite_id
                        or payload.get("started_at") != started_at or payload.get("case_id") != current
                        or payload.get("verified_by") != "guided-evidence-verifier"
                        or payload.get("course_verdict") not in {"PASS","ERR"}
                        or payload.get("case_verified") is not (payload["course_verdict"]=="PASS")
                        or payload.get("task_completed") is not False): raise ValueError("Promptfoo verifier mismatch")
                row = next((r for r in payload["result"]["cases"] if r["case_id"]==current),None)
                if payload["course_verdict"]=="PASS":
                    if row is None or row.get("status")!="PASS" or row.get("case_verified") is not True: raise ValueError("Promptfoo case missing")
                    cases.append(row)
                else:
                    cases.append({"case_id":current,"status":"ERR","reason":payload["reason"]})
                    cases.extend({"case_id":name,"status":"미실행","reason":"앞 케이스 실패로 중단"} for name in names[index+1:])
                    payload["result"]["cases"]=cases
                    return payload
                progress["current_case"]=None
            checked = await native_post(client,f"{VERIFIER_URL}/v1/verify/h13-sequence",json=base,headers=verify_headers)
            if checked.status_code != 200: raise ValueError("Promptfoo final verifier unavailable")
            payload = checked.json()
            if (payload.get("activity_id")!="H13" or payload.get("execution_id")!=suite_id
                    or payload.get("started_at")!=started_at or payload.get("verified_by")!="guided-evidence-verifier"
                    or payload.get("course_verdict") not in {"PASS","ERR"}
                    or payload.get("task_completed") is not (payload["course_verdict"]=="PASS")):
                raise ValueError("Promptfoo final identity mismatch")
            return payload
    except (httpx.HTTPError,ValueError,KeyError,TypeError):
        if len(cases)<len(names):
            cases.append({"case_id":current,"status":"ERR","reason":"현재 케이스의 Promptfoo 원문을 확인하세요."})
            cases.extend({"case_id":name,"status":"미실행","reason":"앞 케이스 실패로 중단"} for name in names[len(cases):])
        return {"activity_id":"H13","execution_id":suite_id,"course_verdict":"ERR","task_completed":False,
            "stage_calls":[],"result":{"cases":cases},"reason":"Promptfoo 실행 또는 독립 검증 응답을 확인하지 못했습니다."}
    finally:
        ACTIVE_SESSIONS.discard(session_id)


async def run_scanner_checks(activity,url,token):
    suite_id=str(uuid.uuid4());started=datetime.now(timezone.utc).isoformat()
    body={"suite_id":suite_id,"started_at":started};cases=[]
    state=NATIVE_SESSION.get();progress=state["native_progress"] if state else {}
    progress.update(total=2,cases=cases,phase="running",current_case={"case_id":"execution-limits","status":"실행 중","started_at":started})
    current="execution-limits"
    try:
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            response=await client.post(url+"/v1/prepare",json=body,headers={"Authorization":f"Bearer {token}"})
            if response.status_code!=200 or response.json().get("suite_id")!=suite_id:raise ValueError()
            progress["phase"]="verifying";progress["current_case"]["status"]="독립 검증 중"
            checked=await client.post(VERIFIER_URL+f"/v1/verify/{activity.lower()}-preflight",json=body,headers={"Authorization":f"Bearer {VERIFIER_TOKEN}"})
            if checked.status_code!=200:raise ValueError()
            payload=checked.json()
            if (payload.get("activity_id")!=activity or payload.get("execution_id")!=suite_id
                    or payload.get("started_at")!=started or payload.get("verified_by")!="guided-evidence-verifier"
                    or payload.get("course_verdict") not in {"PASS","ERR"}
                    or payload.get("case_verified") is not (payload["course_verdict"]=="PASS")):raise ValueError()
            if payload["course_verdict"]=="ERR":
                payload["result"]["cases"]=[{"case_id":current,"status":"ERR","reason":payload["reason"]},{"case_id":"native-tool-report","status":"미실행","reason":"실행 제한 검사 실패로 중단"}]
                return payload
            source=payload["result"]["source_digest"]
            limits=payload["result"].get("config",{})
            cases.append({"case_id":current,"status":"PASS","case_verified":True,"source_digest":source,"execution_limits":limits});current="native-tool-report"
            progress.update(phase="running",current_case={"case_id":current,"status":"실행 중","started_at":datetime.now(timezone.utc).isoformat()})
            executed=await client.post(url+"/v1/run",json=body,headers={"Authorization":f"Bearer {token}"})
            if executed.status_code!=200 or executed.json().get("suite_id")!=suite_id:raise ValueError()
            progress["phase"]="verifying";progress["current_case"]["status"]="독립 검증 중"
            checked=await client.post(VERIFIER_URL+f"/v1/verify/{activity.lower()}",json=body,headers={"Authorization":f"Bearer {VERIFIER_TOKEN}"})
            if checked.status_code!=200:raise ValueError()
            payload=checked.json();result=payload.get("result",{})
            key="config_digest" if activity=="H14" else "source_digest"
            if (payload.get("activity_id")!=activity or payload.get("execution_id")!=suite_id
                    or payload.get("started_at")!=started or payload.get("verified_by")!="guided-evidence-verifier"
                    or payload.get("course_verdict") not in {"PASS","ERR"} or result.get(key)!=source
                    or (payload["course_verdict"]=="PASS" and result.get("execution_limits")!=limits)):raise ValueError()
            result["native_attempts"]=result.get("cases",[])
            cases.append({"case_id":current,"status":payload["course_verdict"],"case_verified":payload["course_verdict"]=="PASS","reason":payload["reason"]})
            result["cases"]=cases
            payload["task_completed"]=payload["course_verdict"]=="PASS"
            return payload
    except (httpx.HTTPError,ValueError,TypeError,KeyError):
        cases.append({"case_id":current,"status":"ERR","reason":"현재 도구 실행 기록을 확인하세요."})
        if current=="execution-limits":cases.append({"case_id":"native-tool-report","status":"미실행","reason":"실행 제한 검사 실패로 중단"})
        return {"activity_id":activity,"execution_id":suite_id,"course_verdict":"ERR","task_completed":False,"stage_calls":[],"result":{"cases":cases},"reason":"현재 실행의 제한 또는 native 보고서 증거가 없습니다."}


async def run_policy_checks(url,token):
    suite_id=str(uuid.uuid4());started=datetime.now(timezone.utc).isoformat()
    body={'suite_id':suite_id,'started_at':started};cases=[]
    names=['normal-business','normal-explanation','risk-marker','risk-paraphrase','promotion-ledger']
    state=NATIVE_SESSION.get();progress=state['native_progress'] if state else {}
    progress.update(total=5,cases=cases,phase='running');current=names[0]
    try:
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            for current in names:
                progress.update(phase='running',current_case={'case_id':current,'status':'실행 중','started_at':datetime.now(timezone.utc).isoformat()})
                final=current=='promotion-ledger'
                sent=body if final else {**body,'case_id':current}
                endpoint='/v1/promote-sequence' if final else '/v1/run-case'
                executed=await client.post(url+endpoint,json=sent,headers={'Authorization':f'Bearer {token}'})
                if executed.status_code!=200 or executed.json().get('suite_id')!=suite_id:raise ValueError()
                progress['phase']='verifying';progress['current_case']['status']='독립 검증 중'
                endpoint='/v1/verify/h16-sequence' if final else '/v1/verify/h16-case'
                checked=await client.post(VERIFIER_URL+endpoint,json=sent,headers={'Authorization':f'Bearer {VERIFIER_TOKEN}'})
                if checked.status_code!=200:raise ValueError()
                payload=checked.json();verdict=payload.get('course_verdict')
                if (payload.get('activity_id')!='H16' or payload.get('execution_id')!=suite_id
                        or payload.get('started_at')!=started or payload.get('verified_by')!='guided-evidence-verifier'
                        or verdict not in {'PASS','HIT','ERR'}
                        or payload.get('case_verified') is not (verdict=='PASS')
                        or payload.get('task_completed') is not (final and verdict=='PASS')):raise ValueError()
                actual=payload.get('result',{}).get('cases',[])
                row={} if final else actual[-1]
                cases.append({**row,'case_id':current,'status':verdict,'case_verified':verdict=='PASS','reason':payload['reason']})
                if verdict!='PASS':
                    cases.extend({'case_id':name,'status':'미실행','reason':'앞 케이스 실패로 중단'} for name in names[len(cases):])
                    payload['result']['cases']=cases;return payload
                if final:
                    payload['result']['cases']=cases;return payload
    except (httpx.HTTPError,ValueError,KeyError,TypeError,IndexError):
        cases.append({'case_id':current,'status':'ERR','reason':'현재 정책 실행과 원장을 확인하세요.'})
        cases.extend({'case_id':name,'status':'미실행','reason':'앞 케이스 실패로 중단'} for name in names[len(cases):])
        return {'activity_id':'H16','execution_id':suite_id,'course_verdict':'ERR','task_completed':False,
                'stage_calls':[],'result':{'cases':cases},'reason':'정책 실행 또는 독립 검증 기록이 없습니다.'}


async def run_tool_activity(activity: str, lab_url: str, lab_token: str) -> dict:
    if activity == "H16" and not EXPLORATION.get():
        return await run_policy_checks(lab_url,lab_token)
    if activity in {"H14","H15"} and not EXPLORATION.get():
        return await run_scanner_checks(activity,lab_url,lab_token)
    suite_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
        executed = await native_post(client, f"{lab_url}/v1/run", json={"suite_id": suite_id, "started_at": started_at}, headers={"Authorization": f"Bearer {lab_token}"})
        if executed.status_code != 200:
            raise HTTPException(status_code=502, detail=f"{activity} runner did not create an artifact")
        if EXPLORATION.get():
            return await exploration_result(executed.json())
        verified = await native_post(client, f"{VERIFIER_URL}/v1/verify/{activity.lower()}", json={"suite_id": suite_id, "started_at": started_at}, headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"})
    if verified.status_code != 200: raise HTTPException(status_code=502, detail="evidence verifier unavailable")
    return verified.json()

@app.post("/api/hands-on/H14/verify")
@app.post("/api/practice/P14/verify")
async def verify_h14(request: Request, session: tuple[str, dict] = Depends(require_csrf)) -> dict:
    if await request.body(): raise HTTPException(422, "verification inputs are server-owned")
    return await run_tool_activity("H14", LAB14_URL, LAB14_TOKEN)

@app.post("/api/hands-on/H15/verify")
@app.post("/api/practice/P15/verify")
async def verify_h15(request: Request, session: tuple[str, dict] = Depends(require_csrf)) -> dict:
    if await request.body(): raise HTTPException(422, "verification inputs are server-owned")
    return await run_tool_activity("H15", LAB15_URL, LAB15_TOKEN)

@app.post("/api/hands-on/H16/verify")
@app.post("/api/practice/P16/verify")
async def verify_h16(request: Request, session: tuple[str, dict] = Depends(require_csrf)) -> dict:
    if await request.body(): raise HTTPException(422, "verification inputs are server-owned")
    return await run_tool_activity("H16", LAB16_URL, LAB16_TOKEN)

async def run_telemetry_checks(url,token):
    suite=str(uuid.uuid4());started=datetime.now(timezone.utc).isoformat();cases=[];children=[]
    names=['normal-lookup','unauthorized-publish','anonymous-lookup'];current=names[0]
    state=NATIVE_SESSION.get();progress=state['native_progress'] if state else {}
    progress.update(total=3,cases=cases,phase='running');source=None
    try:
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            for current in names:
                child={'suite_id':str(uuid.uuid4()),'started_at':datetime.now(timezone.utc).isoformat()}
                sent={**child,'case_id':current}
                progress.update(phase='running',current_case={'case_id':current,'status':'실행 중','started_at':child['started_at']})
                executed=await client.post(url+'/v1/run-case/H17',json=sent,headers={'Authorization':f'Bearer {token}'})
                if executed.status_code!=200 or executed.json().get('suite_id')!=child['suite_id']:raise ValueError()
                progress['phase']='verifying';progress['current_case']['status']='독립 검증 중'
                checked=await client.post(VERIFIER_URL+'/v1/verify/h17-case',json=sent,headers={'Authorization':f'Bearer {VERIFIER_TOKEN}'})
                if checked.status_code!=200:raise ValueError()
                payload=checked.json();verdict=payload.get('course_verdict');actual=payload.get('result',{})
                if (payload.get('activity_id')!='P17' or payload.get('execution_id')!=child['suite_id']
                        or payload.get('started_at')!=child['started_at'] or payload.get('verified_by')!='guided-evidence-verifier'
                        or verdict not in {'PASS','ERR'} or payload.get('case_verified') is not (verdict=='PASS')
                        or payload.get('task_completed') is not False):raise ValueError()
                if verdict=='PASS':
                    if source is not None and source!=actual.get('source_digest'):raise ValueError()
                    source=actual['source_digest'];row=actual['cases'][0]
                else:row={}
                cases.append({**row,'case_id':current,'status':verdict,'case_verified':verdict=='PASS','reason':payload['reason']})
                if verdict=='ERR':
                    cases.extend({'case_id':name,'status':'미실행','reason':'앞 케이스 실패로 중단'} for name in names[len(cases):])
                    payload.update(execution_id=suite,started_at=started);payload['result']['cases']=cases;return payload
                children.append(child)
            checked=await client.post(VERIFIER_URL+'/v1/verify/h17-sequence',json={'suite_id':suite,'started_at':started,'children':children},headers={'Authorization':f'Bearer {VERIFIER_TOKEN}'})
            if checked.status_code!=200:raise ValueError()
            payload=checked.json()
            if (payload.get('activity_id')!='P17' or payload.get('execution_id')!=suite
                    or payload.get('started_at')!=started or payload.get('verified_by')!='guided-evidence-verifier'
                    or payload.get('task_completed') is not (payload.get('course_verdict')=='PASS')):raise ValueError()
            return payload
    except (httpx.HTTPError,ValueError,KeyError,TypeError,IndexError):
        if len(cases)<3:
            cases.append({'case_id':current,'status':'ERR','reason':'현재 요청의 계측 기록을 확인하세요.'})
            cases.extend({'case_id':name,'status':'미실행','reason':'앞 케이스 실패로 중단'} for name in names[len(cases):])
        return {'activity_id':'P17','execution_id':suite,'course_verdict':'ERR','task_completed':False,'stage_calls':[],
            'result':{'cases':cases},'reason':'현재 요청의 실행 또는 계측 검증이 끝나지 않았습니다.'}


async def run_incident_checks(url,token):
    suite=str(uuid.uuid4());started=datetime.now(timezone.utc).isoformat();body={'suite_id':suite,'started_at':started};cases=[]
    names=['0-collected','0-reversed','1-collected','1-reversed','2-collected','2-reversed','missing-log','foreign-trace','open-ledger','duplicate-span'];current=names[0]
    state=NATIVE_SESSION.get();progress=state['native_progress'] if state else {}
    progress.update(total=10,cases=cases,phase='running',current_case={'case_id':current,'status':'관측 자료 준비 중','started_at':started})
    try:
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            prepared=await client.post(url+'/v1/prepare/H19',json=body,headers={'Authorization':f'Bearer {token}'})
            if prepared.status_code!=200 or prepared.json().get('suite_id')!=suite:raise ValueError()
            for current in names:
                sent={**body,'case_id':current};progress.update(phase='running',current_case={'case_id':current,'status':'실행 중','started_at':datetime.now(timezone.utc).isoformat()})
                executed=await client.post(url+'/v1/run-case/H19',json=sent,headers={'Authorization':f'Bearer {token}'})
                if executed.status_code!=200 or executed.json().get('suite_id')!=suite:raise ValueError()
                progress['phase']='verifying';progress['current_case']['status']='독립 검증 중'
                checked=await client.post(VERIFIER_URL+'/v1/verify/h19-case',json=sent,headers={'Authorization':f'Bearer {VERIFIER_TOKEN}'})
                if checked.status_code!=200:raise ValueError()
                payload=checked.json();verdict=payload.get('course_verdict')
                if (payload.get('activity_id')!='P19' or payload.get('execution_id')!=suite
                        or payload.get('started_at')!=started or payload.get('verified_by')!='guided-evidence-verifier'
                        or verdict not in {'PASS','ERR'} or payload.get('case_verified') is not (verdict=='PASS')
                        or payload.get('task_completed') is not False):raise ValueError()
                rows=payload.get('result',{}).get('checks',[]);row=rows[-1] if verdict=='PASS' else {}
                if verdict=='PASS' and row.get('case_id')!=current:raise ValueError()
                cases.append({**row,'case_id':current,'status':verdict,'case_verified':verdict=='PASS','reason':payload['reason']})
                if verdict=='ERR':
                    cases.extend({'case_id':name,'status':'미실행','reason':'앞 케이스 실패로 중단'} for name in names[len(cases):])
                    payload['result']['cases']=cases;return payload
            checked=await client.post(VERIFIER_URL+'/v1/verify/h19',json=body,headers={'Authorization':f'Bearer {VERIFIER_TOKEN}'})
            if checked.status_code!=200:raise ValueError()
            payload=checked.json()
            if (payload.get('activity_id')!='P19' or payload.get('execution_id')!=suite
                    or payload.get('verified_by')!='guided-evidence-verifier'
                    or payload.get('task_completed') is not (payload.get('course_verdict')=='PASS')):raise ValueError()
            payload['result']['cases']=cases;return payload
    except (httpx.HTTPError,ValueError,KeyError,TypeError,IndexError):
        if len(cases)<len(names):
            cases.append({'case_id':current,'status':'ERR','reason':'현재 분석 함수와 관측 원문을 확인하세요.'})
            cases.extend({'case_id':name,'status':'미실행','reason':'앞 케이스 실패로 중단'} for name in names[len(cases):])
        return {'activity_id':'P19','execution_id':suite,'course_verdict':'ERR','task_completed':False,'stage_calls':[],
            'result':{'cases':cases},'reason':'현재 분석 실행 또는 독립 검증이 끝나지 않았습니다.'}


async def run_agent_checks(url,token):
    suite=str(uuid.uuid4());started=datetime.now(timezone.utc).isoformat();body={'suite_id':suite,'started_at':started};cases=[]
    names=['normal','forbidden-model','untrusted-server','forbidden-tool','tool-loop','oversized-result','tool-timeout','foreign-state','wrong-audience'];current=names[0]
    state=NATIVE_SESSION.get();progress=state['native_progress'] if state else {}
    progress.update(total=9,cases=cases,phase='running',current_case={'case_id':current,'status':'관측 자료 준비 중','started_at':started})
    try:
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            for current in names:
                sent={**body,'case_id':current};progress.update(phase='running',current_case={'case_id':current,'status':'실행 중','started_at':datetime.now(timezone.utc).isoformat()})
                executed=await client.post(url+'/v1/run-case',json=sent,headers={'Authorization':f'Bearer {token}'})
                if executed.status_code!=200 or executed.json().get('suite_id')!=suite:raise ValueError()
                progress['phase']='verifying';progress['current_case']['status']='독립 검증 중'
                checked=await client.post(VERIFIER_URL+'/v1/verify/h21-case',json=sent,headers={'Authorization':f'Bearer {VERIFIER_TOKEN}'})
                if checked.status_code!=200:raise ValueError()
                payload=checked.json();verdict=payload.get('course_verdict')
                if (payload.get('activity_id')!='H21' or payload.get('execution_id')!=suite
                        or payload.get('started_at')!=started or payload.get('verified_by')!='guided-evidence-verifier'
                        or verdict not in {'PASS','HIT','ERR'} or payload.get('case_verified') is not (verdict=='PASS')
                        or payload.get('task_completed') is not False):raise ValueError()
                rows=payload.get('result',{}).get('cases',[]);row=next((item for item in rows if item.get('case_id')==current),{})
                if verdict=='PASS' and row.get('case_id')!=current:raise ValueError()
                cases.append({**row,'native_reason':row.get('reason'),'case_id':current,'status':verdict,'case_verified':verdict=='PASS','reason':payload['reason']})
                if verdict!='PASS':
                    cases.extend({'case_id':name,'status':'미실행','reason':'앞 케이스 실패로 중단'} for name in names[len(cases):])
                    payload['result']['cases']=cases;return payload
            checked=await client.post(VERIFIER_URL+'/v1/verify/lab-21',json=body,headers={'Authorization':f'Bearer {VERIFIER_TOKEN}'})
            if checked.status_code!=200:raise ValueError()
            payload=checked.json()
            if (payload.get('activity_id')!='H21' or payload.get('execution_id')!=suite
                    or payload.get('verified_by')!='guided-evidence-verifier'
                    or payload.get('task_completed') is not (payload.get('course_verdict')=='PASS')):raise ValueError()
            payload['result']['cases']=cases;return payload
    except (httpx.HTTPError,ValueError,KeyError,TypeError,IndexError):
        if len(cases)<len(names):
            cases.append({'case_id':current,'status':'ERR','reason':'현재 분석 함수와 관측 원문을 확인하세요.'})
            cases.extend({'case_id':name,'status':'미실행','reason':'앞 케이스 실패로 중단'} for name in names[len(cases):])
        return {'activity_id':'H21','execution_id':suite,'course_verdict':'ERR','task_completed':False,'stage_calls':[],
            'result':{'cases':cases},'reason':'현재 분석 실행 또는 독립 검증이 끝나지 않았습니다.'}


async def run_approval_checks(url,token):
    suite=str(uuid.uuid4());started=datetime.now(timezone.utc).isoformat();body={'suite_id':suite,'started_at':started};cases=[]
    names=['normal','no-approval','self-approval','changed-args','expired','approved','reuse'];current=names[0]
    state=NATIVE_SESSION.get();progress=state['native_progress'] if state else {}
    progress.update(total=7,cases=cases,phase='running',current_case={'case_id':current,'status':'관측 자료 준비 중','started_at':started})
    try:
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            for current in names:
                sent={**body,'case_id':current};progress.update(phase='running',current_case={'case_id':current,'status':'실행 중','started_at':datetime.now(timezone.utc).isoformat()})
                executed=await client.post(url+'/v1/run-case',json=sent,headers={'Authorization':f'Bearer {token}'})
                if executed.status_code!=200 or executed.json().get('suite_id')!=suite:raise ValueError()
                progress['phase']='verifying';progress['current_case']['status']='독립 검증 중'
                checked=await client.post(VERIFIER_URL+'/v1/verify/h22-case',json=sent,headers={'Authorization':f'Bearer {VERIFIER_TOKEN}'})
                if checked.status_code!=200:raise ValueError()
                payload=checked.json();verdict=payload.get('course_verdict')
                if (payload.get('activity_id')!='H22' or payload.get('execution_id')!=suite
                        or payload.get('started_at')!=started or payload.get('verified_by')!='guided-evidence-verifier'
                        or verdict not in {'PASS','HIT','ERR'} or payload.get('case_verified') is not (verdict=='PASS')
                        or payload.get('task_completed') is not False):raise ValueError()
                actual=payload.get('result',{});key={'no-approval':'no_approval','self-approval':'self_approval','changed-args':'changed_args'}.get(current,current)
                if verdict=='PASS' and actual.get('case_order')!=names[:names.index(current)+1]:raise ValueError()
                row={'response':actual[key],'effect_counts':actual['effect_counts'],'verified_effects':actual['verified_effects']} if key in actual else {}
                cases.append({**row,'case_id':current,'status':verdict,'case_verified':verdict=='PASS','reason':payload['reason']})
                if verdict!='PASS':
                    cases.extend({'case_id':name,'status':'미실행','reason':'앞 케이스 실패로 중단'} for name in names[len(cases):])
                    payload['result']['cases']=cases;return payload
            checked=await client.post(VERIFIER_URL+'/v1/verify/lab-22',json=body,headers={'Authorization':f'Bearer {VERIFIER_TOKEN}'})
            if checked.status_code!=200:raise ValueError()
            payload=checked.json()
            if (payload.get('activity_id')!='H22' or payload.get('execution_id')!=suite
                    or payload.get('verified_by')!='guided-evidence-verifier'
                    or payload.get('task_completed') is not (payload.get('course_verdict')=='PASS')):raise ValueError()
            payload['result']['cases']=cases;return payload
    except (httpx.HTTPError,ValueError,KeyError,TypeError,IndexError):
        if len(cases)<len(names):
            cases.append({'case_id':current,'status':'ERR','reason':'현재 분석 함수와 관측 원문을 확인하세요.'})
            cases.extend({'case_id':name,'status':'미실행','reason':'앞 케이스 실패로 중단'} for name in names[len(cases):])
        return {'activity_id':'H22','execution_id':suite,'course_verdict':'ERR','task_completed':False,'stage_calls':[],
            'result':{'cases':cases},'reason':'현재 분석 실행 또는 독립 검증이 끝나지 않았습니다.'}


async def run_query_checks(url,token):
    suite=str(uuid.uuid4());started=datetime.now(timezone.utc).isoformat();body={'suite_id':suite,'started_at':started};cases=[]
    names=['normal-query','denied-query'];current=names[0]
    state=NATIVE_SESSION.get();progress=state['native_progress'] if state else {}
    progress.update(total=2,cases=cases,phase='running',current_case={'case_id':current,'status':'관측 자료 준비 중','started_at':started})
    try:
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            prepared=await client.post(url+'/v1/prepare/H18',json=body,headers={'Authorization':f'Bearer {token}'})
            if prepared.status_code!=200 or prepared.json().get('suite_id')!=suite:raise ValueError()
            for current in names:
                sent={**body,'case_id':current};progress.update(phase='running',current_case={'case_id':current,'status':'실행 중','started_at':datetime.now(timezone.utc).isoformat()})
                executed=await client.post(url+'/v1/run-case/H18',json=sent,headers={'Authorization':f'Bearer {token}'})
                if executed.status_code!=200 or executed.json().get('suite_id')!=suite:raise ValueError()
                progress['phase']='verifying';progress['current_case']['status']='독립 검증 중'
                checked=await client.post(VERIFIER_URL+'/v1/verify/h18-case',json=sent,headers={'Authorization':f'Bearer {VERIFIER_TOKEN}'})
                if checked.status_code!=200:raise ValueError()
                payload=checked.json();verdict=payload.get('course_verdict')
                if (payload.get('activity_id')!='P18' or payload.get('execution_id')!=suite
                        or payload.get('started_at')!=started or payload.get('verified_by')!='guided-evidence-verifier'
                        or verdict not in {'PASS','ERR'} or payload.get('case_verified') is not (verdict=='PASS')
                        or payload.get('task_completed') is not False):raise ValueError()
                rows=payload.get('result',{}).get('cases',[]);row=rows[-1] if verdict=='PASS' else {}

                cases.append({**row,'case_id':current,'status':verdict,'case_verified':verdict=='PASS','reason':payload['reason']})
                if verdict=='ERR':
                    cases.extend({'case_id':name,'status':'미실행','reason':'앞 케이스 실패로 중단'} for name in names[len(cases):])
                    payload['result']['cases']=cases;return payload
            checked=await client.post(VERIFIER_URL+'/v1/verify/h18',json=body,headers={'Authorization':f'Bearer {VERIFIER_TOKEN}'})
            if checked.status_code!=200:raise ValueError()
            payload=checked.json()
            if (payload.get('activity_id')!='P18' or payload.get('execution_id')!=suite
                    or payload.get('verified_by')!='guided-evidence-verifier'
                    or payload.get('task_completed') is not (payload.get('course_verdict')=='PASS')):raise ValueError()
            payload['result']['cases']=cases;return payload
    except (httpx.HTTPError,ValueError,KeyError,TypeError,IndexError):
        if len(cases)<len(names):
            cases.append({'case_id':current,'status':'ERR','reason':'현재 분석 함수와 관측 원문을 확인하세요.'})
            cases.extend({'case_id':name,'status':'미실행','reason':'앞 케이스 실패로 중단'} for name in names[len(cases):])
        return {'activity_id':'P18','execution_id':suite,'course_verdict':'ERR','task_completed':False,'stage_calls':[],
            'result':{'cases':cases},'reason':'현재 분석 실행 또는 독립 검증이 끝나지 않았습니다.'}


async def run_alert_checks(url,token):
    suite=str(uuid.uuid4());started=datetime.now(timezone.utc).isoformat();body={'suite_id':suite,'started_at':started};cases=[]
    state=NATIVE_SESSION.get();progress=state['native_progress'] if state else {}
    progress.update(total=2,cases=cases,phase='verifying',current_case={'case_id':'configuration-binding','status':'독립 검증 중','started_at':started})
    current='configuration-binding'
    try:
        if not token:raise ValueError('activity connection missing')
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            checked=await client.post(VERIFIER_URL+'/v1/verify/h20-preflight',json=body,headers={'Authorization':f'Bearer {VERIFIER_TOKEN}'})
            if checked.status_code!=200:raise ValueError()
            payload=checked.json();verdict=payload.get('course_verdict')
            if (payload.get('activity_id')!='P20' or payload.get('execution_id')!=suite
                    or payload.get('started_at')!=started or payload.get('verified_by')!='guided-evidence-verifier'
                    or verdict not in {'PASS','ERR'} or payload.get('case_verified') is not (verdict=='PASS')
                    or payload.get('task_completed') is not False):raise ValueError()
            cases.append({'case_id':current,'status':verdict,'case_verified':verdict=='PASS','reason':payload['reason'],'configuration':dict(payload.get('result',{}))})
            if verdict=='ERR':
                cases.append({'case_id':'alert-lifecycle','status':'미실행','reason':'설정 적용 검사 실패로 중단'});payload['result']['cases']=cases;return payload
            source=payload['result']['source_digest'];current='alert-lifecycle'
            progress.update(phase='running',current_case={'case_id':current,'status':'실행 중','started_at':datetime.now(timezone.utc).isoformat()})
            executed=await client.post(url+'/v1/run/H20',json=body,headers={'Authorization':f'Bearer {token}'})
            if executed.status_code!=200 or executed.json().get('suite_id')!=suite:raise ValueError()
            progress['phase']='verifying';progress['current_case']['status']='독립 검증 중'
            checked=await client.post(VERIFIER_URL+'/v1/verify/h20',json=body,headers={'Authorization':f'Bearer {VERIFIER_TOKEN}'})
            if checked.status_code!=200:raise ValueError()
            payload=checked.json();verdict=payload.get('course_verdict');result=payload.get('result',{})
            if (payload.get('activity_id')!='P20' or payload.get('execution_id')!=suite
                    or payload.get('started_at')!=started or payload.get('verified_by')!='guided-evidence-verifier'
                    or verdict not in {'PASS','ERR'} or payload.get('task_completed') is not (verdict=='PASS')
                    or (verdict=='PASS' and result.get('source_digest')!=source)):raise ValueError()
            result['native_requests']=result.get('receipt',{}).get('cases',[])
            cases.append({'case_id':current,'status':verdict,'case_verified':verdict=='PASS','reason':payload['reason']})
            result['cases']=cases;return payload
    except (httpx.HTTPError,ValueError,KeyError,TypeError,IndexError):
        cases.append({'case_id':current,'status':'ERR','reason':'현재 경보 실행과 제품 원문을 확인하세요.'})
        if current=='configuration-binding':cases.append({'case_id':'alert-lifecycle','status':'미실행','reason':'설정 적용 검사 실패로 중단'})
        return {'activity_id':'P20','execution_id':suite,'course_verdict':'ERR','task_completed':False,'stage_calls':[],
            'result':{'cases':cases},'reason':'설정 검사 또는 실제 경보 발생·해제 검증이 끝나지 않았습니다.'}


async def run_observability_activity(activity: str) -> dict:
    if not EXPLORATION.get():
        runner = {'H17': (run_telemetry_checks, H17_URL, H17_TOKEN),
                  'H18': (run_query_checks, H18_URL, H18_TOKEN),
                  'H19': (run_incident_checks, H19_URL, H19_TOKEN),
                  'H20': (run_alert_checks, H20_URL, H20_TOKEN)}[activity]
        result = await runner[0](runner[1], runner[2])
        # Case/preflight verifiers use course_verdict internally.  The public
        # grading envelope always exposes the same verdict as security_verdict.
        result.setdefault('security_verdict', result.get('course_verdict', 'ERR'))
        result.setdefault('next_check', '실패한 요구사항과 미실행 사례를 확인하세요.')
        return result
    suite_id=str(uuid.uuid4()); started_at=datetime.now(timezone.utc).isoformat()
    url,token={'H17': (H17_URL,H17_TOKEN), 'H18': (H18_URL,H18_TOKEN), 'H19': (H19_URL,H19_TOKEN),
               'H20': (H20_URL,H20_TOKEN)}[activity]
    stopped_stage = 'learner_execution'
    try:
        if not token:
            raise ValueError('activity connection is not configured')
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            executed=await native_post(client, f"{url}/v1/run/{activity}",json={"suite_id":suite_id,"started_at":started_at},headers={"Authorization":f"Bearer {token}"})
            if executed.status_code != 200:
                raise ValueError('learner response unavailable')
            stopped_stage = 'evidence_verification'
            if EXPLORATION.get():
                return await exploration_result(executed.json())
            verified=await native_post(client, f"{VERIFIER_URL}/v1/verify/{activity.lower()}",json={"suite_id":suite_id,"started_at":started_at},headers={"Authorization":f"Bearer {VERIFIER_TOKEN}"})
        if verified.status_code != 200:
            raise ValueError('verifier response unavailable')
        return verified.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(502, detail={
            'activity_id': activity.replace('H', 'P', 1), 'internal_activity_id': activity,
            'task_completed': False, 'security_verdict': 'ERR', 'course_verdict': 'ERR',
            'stopped_stage': stopped_stage,
            'reason': '실행 또는 검증 응답을 받지 못했습니다. 기록을 확인하기 전에는 뒤 호출 여부를 단정할 수 없습니다.',
            'next_check': ('해당 문제 컨테이너의 실행 상태를 확인합니다.' if stopped_stage == 'learner_execution'
                           else '검증기 컨테이너의 실행 상태를 확인합니다.'),
        }) from None

@app.post("/api/hands-on/H17/verify")
@app.post("/api/practice/P17/verify")
async def verify_h17(request:Request,session:tuple[str,dict]=Depends(require_csrf))->dict:
    if await request.body(): raise HTTPException(422,"verification inputs are server-owned")
    return await run_observability_activity('H17')
@app.post("/api/hands-on/H18/verify")
@app.post("/api/practice/P18/verify")
async def verify_h18(request:Request,session:tuple[str,dict]=Depends(require_csrf))->dict:
    if await request.body(): raise HTTPException(422,"verification inputs are server-owned")
    return await run_observability_activity('H18')
@app.post("/api/hands-on/H19/verify")
@app.post("/api/practice/P19/verify")
async def verify_h19(request:Request,session:tuple[str,dict]=Depends(require_csrf))->dict:
    if await request.body(): raise HTTPException(422,"verification inputs are server-owned")
    return await run_observability_activity('H19')
@app.post("/api/hands-on/H20/verify")
@app.post("/api/practice/P20/verify")
async def verify_h20(request:Request,session:tuple[str,dict]=Depends(require_csrf))->dict:
    if await request.body(): raise HTTPException(422,"verification inputs are server-owned")
    return await run_observability_activity('H20')

@app.post("/api/hands-on/H22/verify")
@app.post("/api/practice/P22/verify")
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
        if not EXPLORATION.get():return await run_approval_checks(H22_HOST_URL,H22_TOKEN)
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            run_response = await native_post(client,
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
            if EXPLORATION.get():
                return await exploration_result(run_response.json())
            verifier_response = await native_post(client,
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
@app.post("/api/practice/P21/verify")
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
        if not EXPLORATION.get():return await run_agent_checks(H21_HOST_URL,H21_TOKEN)
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            run_response = await native_post(client,
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
            if EXPLORATION.get():
                return await exploration_result(run_response.json())
            verifier_response = await native_post(client,
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


@app.post("/api/practice/P23/verify")
async def verify_model_call(request: Request, session: tuple[str,dict] = Depends(require_session), x_csrf_token: str | None = Header(None)):
    require_csrf(request,x_csrf_token,session)
    if await request.body():
        raise HTTPException(422,"verification inputs are server-owned")
    execution=str(uuid.uuid4())
    session[1]["p23_case_progress"]={"suite_id":execution,"phase":"running","total":3,"cases":[],"current_case":None}
    token=hmac.new(LAB_TOKEN.encode(), b"model-call:P23", "sha256").hexdigest()
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, trust_env=False, follow_redirects=False) as client:
            response=await native_post(client, "http://guided-model-call:8000/v1/run-suite",headers={"Authorization":"Bearer "+token},json={"execution_id":execution})
            response.raise_for_status()
            verified=await native_post(client, VERIFIER_URL+"/v1/verify/p23",headers={"Authorization":"Bearer "+VERIFIER_TOKEN},json={"execution_id":execution})
            verified.raise_for_status()
        payload=verified.json()
        if payload.get("execution_id") != execution or payload.get("activity_id") != "P23" or payload.get("verified_by") != "guided-evidence-verifier":
            raise ValueError("verifier identity mismatch")
        session[1]["p23_case_progress"]={"suite_id":execution,"phase":"finished","total":3,
            "cases":payload.get("result",{}).get("cases",[]),"current_case":None,"verdict":payload.get("course_verdict","ERR")}
        return payload
    except (httpx.HTTPError,ValueError):
        session[1]["p23_case_progress"].update(phase="finished",current_case=None,verdict="ERR")
        return {"activity_id":"P23","execution_id":execution,"task_completed":False,"security_verdict":"ERR","course_verdict":"ERR","next_check":"모델 연결 앱·검증기와 AWS 호출 권한을 확인하세요."}

@app.get("/api/test-progress/P23")
async def p23_case_progress(session: tuple[str,dict] = Depends(require_session)):
    state=session[1].get("p23_case_progress")
    if not state:
        return {"suite_id":None,"phase":"idle","total":3,"cases":[],"current_case":None}
    if state.get("phase") != "running":
        return state
    token=hmac.new(LAB_TOKEN.encode(),b"model-call:P23","sha256").hexdigest()
    try:
        async with httpx.AsyncClient(timeout=5,trust_env=False,follow_redirects=False) as client:
            response=await client.get(f"http://guided-model-call:8000/v1/progress/{state['suite_id']}",headers={"Authorization":"Bearer "+token})
        if response.status_code == 200 and response.json().get("suite_id") == state["suite_id"]:
            return response.json()
    except httpx.HTTPError:
        pass
    return state


class ModelCallChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=4000)

@app.post("/api/practice/P23/chat")
async def experience_model_call(body: ModelCallChatRequest, request: Request,
    session: tuple[str,dict] = Depends(require_csrf)):
    token=hmac.new(LAB_TOKEN.encode(),b"model-call:P23","sha256").hexdigest()
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT,trust_env=False,follow_redirects=False) as client:
            response=await native_post(client, "http://guided-model-call:8000/v1/chat",headers={"Authorization":"Bearer "+token},json=body.model_dump())
        payload=response.json()
        if response.status_code != 200:
            raise HTTPException(response.status_code, payload.get("detail","모델 연결 앱 응답을 확인하세요."))
        if payload.get("graded") is not False or not isinstance(payload.get("reply"),str):
            raise ValueError("invalid exploration response")
        return payload
    except (httpx.HTTPError,ValueError):
        raise HTTPException(502,"모델 연결 앱에서 응답을 받지 못했습니다.")


@app.post("/api/experience/{problem}")
async def experience_activity(problem: str, request: Request, session: tuple[str, dict] = Depends(require_csrf)):
    handlers = {
        "P05": verify_h05_dialog_rail,
        "P06": verify_h06_python_action, "P07": verify_h07_content_safety,
        "P08": verify_h08_self_check_input, "P09": verify_h09_presidio_delivery,
        "P10": verify_h10_output_rail, "P11": verify_h11_rag_provenance,
        "P12": verify_h12_application_pipeline, "P13": verify_h13_promptfoo,
        "P14": verify_h14, "P15": verify_h15, "P16": verify_h16,
        "P17": verify_h17, "P18": verify_h18, "P19": verify_h19,
        "P20": verify_h20, "P21": verify_h21_agent_policy, "P22": verify_h22_mcp_server,
    }
    if problem not in handlers:
        raise HTTPException(404, "이 미션은 전용 직접 테스트 화면을 사용합니다.")
    raw=await request.body()
    try:
        body=json.loads(raw) if raw else {}
    except ValueError:
        raise HTTPException(422,"입력 형식을 확인하세요.") from None
    if not isinstance(body,dict):raise HTTPException(422,"입력 형식을 확인하세요.")
    catalog=load_experience_catalog().get(problem,{})
    mode=catalog.get("mode")
    allowed={"message","stage"} if problem=="P09" else {"message"} if mode=="message" else {"operation","message"} if mode=="operation" else ({"case_id","message"} if catalog.get("editable") else {"case_id"}) if mode=="scenario" else set()
    if set(body)-allowed:raise HTTPException(422,"정책·권한·자원 ID는 서버가 관리합니다.")
    if mode in {"message","operation"} and (not isinstance(body.get("message"),str) or not body["message"].strip() or not 1<=len(body["message"])<=(200 if problem=="P22" else 2000 if problem=="P09" else 1000)):
        raise HTTPException(422,"문장을 입력하세요.")
    if mode=="scenario" and body.get("case_id") not in {item["id"] for item in catalog["options"]}:
        raise HTTPException(422,"실행할 사례를 선택하세요.")
    if catalog.get("editable") and "message" in body and (not isinstance(body["message"],str) or not body["message"].strip() or len(body["message"])>1000):raise HTTPException(422,"1~1000자의 문장을 입력하세요.")
    if problem=="P09" and body.get("stage","input") not in {"input","output"}:raise HTTPException(422,"검사 위치를 선택하세요.")
    if mode=="operation" and body.get("operation") not in {item["id"] for item in catalog["options"]}:raise HTTPException(422,"실행할 기능을 선택하세요.")
    if problem in {"P05","P09","P11","P16","P21","P22"}:
        return await native_preview(problem,({"case_id":body["case_id"],**({"query":body["message"]} if "message" in body else {})} if problem=="P11" else body),session)
    # Existing bounded tool scans are real features; they do not award completion.
    selected_context=PREVIEW_CASE.set(body.get("case_id"))
    message_context=PREVIEW_MESSAGE.set(body.get("message") if catalog.get("editable") else None)
    request=Request(request.scope);request._body=b""
    owns_resource_lock = problem in {"P02", "P03", "P04"}
    if owns_resource_lock:
        if problem in RESOURCE_ACTIONS:
            raise HTTPException(409, "이 미션의 AWS 작업 또는 실행이 진행 중입니다.")
        RESOURCE_ACTIONS.add(problem)
    context = EXPLORATION.set(problem)
    try:
        return await handlers[problem](request, session)
    finally:
        EXPLORATION.reset(context)
        PREVIEW_CASE.reset(selected_context)
        PREVIEW_MESSAGE.reset(message_context)
        if owns_resource_lock:
            RESOURCE_ACTIONS.discard(problem)


@app.get("/api/resource-status/{problem}")
async def resource_status(problem: str, request: Request):
    session_from_cookie(request.cookies.get("guided_session"))
    tokens = {"P02": H02_PROVISION_TOKEN, "P03": H03_PROVISION_TOKEN, "P04": H04_PROVISION_TOKEN}
    if problem not in tokens:
        raise HTTPException(404, detail="unsupported mission")
    try:
        async with httpx.AsyncClient(timeout=180, trust_env=False) as client:
            response = await client.get(f"{GATEWAY_URL}/v1/resource-status/{problem}",
                                       headers={"Authorization": f"Bearer {tokens[problem]}"})
        if response.status_code == 409:
            raise HTTPException(409, detail="AWS 자원 작업이 진행 중입니다. 완료 후 확인하세요.")
        if response.status_code != 200:
            raise HTTPException(502, detail="AWS 상태 조회에 실패했습니다. AWS 자격 증명과 조회 권한을 확인하세요.")
        result = response.json()
        if result.get("practice_id") != problem or result.get("read_only") is not True:
            raise HTTPException(502, detail="AWS 상태 응답이 일치하지 않습니다.")
        return result
    except httpx.RequestError as error:
        raise HTTPException(502, detail="AWS 상태 조회 서비스에 연결하지 못했습니다.") from error


class KnowledgeSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=1000)


@app.post("/api/knowledge/search")
async def search_knowledge(body: KnowledgeSearchRequest, request: Request,
                           session: tuple[str, dict] = Depends(require_csrf)):
    if not body.query.strip():
        raise HTTPException(422, "검색어를 입력하세요.")
    if "P03" in RESOURCE_ACTIONS or session[0] in ACTIVE_SESSIONS:
        raise HTTPException(409, "검색 또는 AWS 자원 작업이 진행 중입니다.")
    RESOURCE_ACTIONS.add("P03")
    ACTIVE_SESSIONS.add(session[0])
    try:
        async with httpx.AsyncClient(timeout=110, trust_env=False, follow_redirects=False) as client:
            response = await client.post(f"{LAB03_URL}/v1/search", json=body.model_dump(),
                                        headers={"Authorization": f"Bearer {LAB03_TOKEN}"})
        if response.status_code != 200:
            messages = {
                409: "검색 미실행 — AWS 자원 준비가 필요하거나 다른 작업이 진행 중입니다. 자원 준비 상태를 확인하세요.",
                401: "검색 미실행 — 검색 앱 인증에 실패했습니다.",
                404: "검색 미실행 — 검색 앱에 검색 API가 없습니다. 검색 앱을 최신 코드로 빌드·적용하세요.",
                503: "검색 미실행 — 검색 앱을 사용할 수 없습니다.",
            }
            if response.status_code == 409:
                detail = response.json().get("detail")
                if detail in {"검색 미실행 — AWS 자원의 준비 기록이 없습니다. AWS 자원 준비를 완료한 뒤 다시 검색하세요.", "P03 execution already running"}:
                    messages[409] = detail if detail.startswith("검색") else "검색 미실행 — 다른 검색·채점 작업이 진행 중입니다. 완료 후 다시 검색하세요."
            raise HTTPException(response.status_code if response.status_code == 409 else 502,
                                messages.get(response.status_code, "검색이 완료되지 않았습니다. 검색 앱 오류로 결과를 받지 못했습니다."))
        payload = response.json()
        if payload.get("practice_id") != "P03" or payload.get("graded") is not False or payload.get("query") != body.query.strip():
            raise ValueError("search identity mismatch")
        return payload
    except (httpx.HTTPError, ValueError):
        raise HTTPException(502, "검색 실행 앱에 연결하지 못했습니다.")
    finally:
        RESOURCE_ACTIONS.discard("P03")
        ACTIVE_SESSIONS.discard(session[0])


class DocumentUploadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=10, max_length=4000)


@app.post("/api/documents/upload")
async def upload_document(body: DocumentUploadRequest, request: Request,
                          session: tuple[str, dict] = Depends(require_csrf)):
    if "P02" in RESOURCE_ACTIONS or session[0] in ACTIVE_SESSIONS:
        raise HTTPException(409, "문서 또는 AWS 자원 작업이 진행 중입니다." )
    RESOURCE_ACTIONS.add("P02")
    ACTIVE_SESSIONS.add(session[0])
    try:
        async with httpx.AsyncClient(timeout=100, trust_env=False, follow_redirects=False) as client:
            response = await client.post(f"{LAB02_URL}/v1/upload", json=body.model_dump(),
                                        headers={"Authorization": f"Bearer {LAB02_TOKEN}"})
        if response.status_code != 200:
            raise HTTPException(502, "문서 실행 앱 응답을 확인하세요.")
        payload = response.json()
        if payload.get("practice_id") != "P02" or payload.get("graded") is not False:
            raise ValueError("upload identity mismatch")
        return payload
    except (httpx.HTTPError, ValueError):
        raise HTTPException(502, "문서 실행 앱에 연결하지 못했습니다.")
    finally:
        RESOURCE_ACTIONS.discard("P02")
        ACTIVE_SESSIONS.discard(session[0])


class GuardrailChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=1000)


@app.post("/api/practice/P04/chat")
async def guardrail_chat(body: GuardrailChatRequest, request: Request,
                         session: tuple[str, dict] = Depends(require_csrf)):
    if not body.message.strip():
        raise HTTPException(422, "질문을 입력하세요.")
    if "P04" in RESOURCE_ACTIONS or session[0] in ACTIVE_SESSIONS:
        raise HTTPException(409, "다른 질문·자원 작업이 진행 중입니다.")
    RESOURCE_ACTIONS.add("P04")
    ACTIVE_SESSIONS.add(session[0])
    try:
        async with httpx.AsyncClient(timeout=110, trust_env=False, follow_redirects=False) as client:
            response = await client.post(f"{LAB04_URL}/v1/chat", json=body.model_dump(),
                headers={"Authorization": f"Bearer {LAB04_TOKEN}"})
        if response.status_code != 200:
            raise HTTPException(409 if response.status_code == 409 else 502,
                "모델 호출이 완료되지 않았습니다. AWS Guardrail 준비 상태를 확인하세요.")
        result = response.json()
        if result.get("practice_id") != "P04" or result.get("graded") is not False or result.get("message") != body.message:
            raise ValueError("direct response mismatch")
        return result
    except (httpx.HTTPError, ValueError):
        raise HTTPException(502, "모델 호출 결과를 받지 못했습니다.") from None
    finally:
        RESOURCE_ACTIONS.discard("P04")
        ACTIVE_SESSIONS.discard(session[0])


def load_experience_catalog():
    path=ROOT/"experience.json"
    return json.loads(path.read_text()) if path.is_file() else {}

@app.get("/api/case-catalog")
def case_catalog(session:tuple[str,dict]=Depends(require_session)):
    return json.loads((ROOT/"case-catalog.json").read_text())

@app.get("/api/experience-catalog")
def experience_catalog(session:tuple[str,dict]=Depends(require_session)):
    return load_experience_catalog()

async def native_preview(problem,body,session):
    if session[0] in ACTIVE_SESSIONS:raise HTTPException(409,"현재 실행이 끝난 뒤 다시 요청하세요.")
    ACTIVE_SESSIONS.add(session[0])
    number=int(problem[1:])
    url=globals()[f"LAB{number:02d}_URL"] if number<=16 else globals()[f"H{number}_HOST_URL"]
    token=globals()[f"LAB{number:02d}_TOKEN"] if number<=16 else globals()[f"H{number}_TOKEN"]
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT,trust_env=False,follow_redirects=False) as client:
            response=await client.post(url+"/v1/preview",json=body,headers={"Authorization":"Bearer "+token})
        if response.status_code!=200:raise HTTPException(502,"기능 실행이 완료되지 않았습니다. 적용한 코드·정책과 RAW 응답을 확인하세요.")
        result=response.json()
        if result.get("graded") is not False:raise HTTPException(502,"직접 테스트 응답 형식이 다릅니다.")
        return {"graded":False,"result":clean_experience(result)}
    except httpx.HTTPError:
        raise HTTPException(502,"해당 미션 서비스에 연결하지 못했습니다.") from None
    finally:ACTIVE_SESSIONS.discard(session[0])

async def native_post(client,url,**kwargs):
    session=NATIVE_SESSION.get();body=kwargs.get("json") or {}
    running=url.rstrip('/').endswith(('/v1/run','/v1/run-suite')) or '/v1/run/H' in url
    if PREVIEW_CASE.get() and running:
        kwargs['headers']={**kwargs.get('headers',{}),'X-Preview-Case':PREVIEW_CASE.get(),**({'X-Preview-Message':base64.urlsafe_b64encode(PREVIEW_MESSAGE.get().encode()).decode()} if PREVIEW_MESSAGE.get() else {})}
    state=session.get('native_progress') if session else None
    if state and running:
        key=body.get('suite_id') or body.get('execution_id') or state['suite_id']
        state['suite_id']=key;state['phase']='running'
        state['current_case']={'case_id':body.get('case_id') or '현재 기능 실행','status':'실행 중','started_at':datetime.now(timezone.utc).isoformat()}
        state['total']=len(body.get('cases',body.get('execution_ids',[]))) or state.get('total')
        session['_native_target']={'url':url.rsplit('/v1/',1)[0]+'/v1/progress/'+key,'headers':kwargs.get('headers',{})}
        kwargs['headers']={**kwargs.get('headers',{}),'X-Progress-Id':key}
    if state and '/v1/verify/' in url:
        state['phase']='verifying'
        if body.get('case_id'):
            current=state.get('current_case') or {}
            state['current_case']={**(current if current.get('case_id')==body['case_id'] else {}),
                'case_id':body['case_id'],'status':'독립 검증 중'}
        else:
            state['current_case']=None
    response=await client.post(url,**kwargs)
    diagnostic_state=DIAGNOSTIC_STATE.get()
    if response.status_code >= 500 and diagnostic_state is not None:
        try:
            value=response.json()
            detail=value.get("detail")
            observed=value.get("diagnosis") or (detail.get("diagnosis") if isinstance(detail,dict) else None)
            if isinstance(observed,dict): diagnostic_state["diagnosis"]=observed
        except (ValueError,AttributeError): pass
    if state and running and body.get('case_id'):
        state['cases'].append({'case_id':body['case_id'],'status':'실행 완료' if response.status_code==200 else 'ERR','reason':'독립 검증 대기'})
        state['current_case']=None
    return response

@app.get('/api/test-progress/{problem}')
async def native_case_progress(problem:str,session:tuple[str,dict]=Depends(require_session)):
    if problem not in load_experience_catalog():raise HTTPException(404,'unknown mission')
    state=session[1].get('native_progress')
    if not state or state.get("problem")!=problem:return {'phase':'idle','suite_id':None,'cases':[],'total':None}
    target=session[1].get('_native_target')
    if target:
        try:
            async with httpx.AsyncClient(timeout=3,trust_env=False) as client:
                response=await client.get(target['url'],headers=target['headers'])
            if response.status_code==200:
                progress=response.json()
                if progress.get('suite_id')==state['suite_id']:
                    state['cases']=progress.get('cases',[])
                    state['total']=progress.get('total')
                    return {**progress,'phase':state['phase'] if state['phase'] in {'verifying','finished'} else progress['phase']}
        except (httpx.HTTPError,ValueError,KeyError):pass
    return state
