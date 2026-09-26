"""Same-origin learning UI orchestrator for the tenant 03 vertical slice."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
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
P01_PATH = ROOT / "p01.json"
if not P01_PATH.exists():
    P01_PATH = ROOT.parent / "guided-contracts/p01.json"
P01_CONTRACT = json.loads(P01_PATH.read_text())
APP_VERSION = os.getenv("RELEASE_VERSION", os.getenv("APP_VERSION", "dev"))
SESSION_SECRET = os.environ["GUIDED_SESSION_SECRET"].encode()
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
    response = await call_next(request)
    parts = request.url.path.strip("/").split("/")
    if (len(parts) == 4 and parts[:2] == ["api", "practice"]
            and parts[2] in {f"P{number:02d}" for number in range(1, 23)}
            and parts[3] == "verify" and response.status_code == 200):
        body = b"".join([chunk async for chunk in response.body_iterator])
        payload = practice_envelope(json.loads(body), parts[2])
        headers = {key: value for key, value in response.headers.items()
                   if key.lower() != "content-length"}
        response = JSONResponse(content=payload, status_code=200, headers=headers,
                                background=response.background)
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
    payload = {
        "csrf_token": session[1]["csrf"],
        "workspace": "practice",
        "course": {
            "tabs": 13,
            "practices": 22,
            "practice_ids": [f"P{number:02d}" for number in range(1, 23)],
            "execution_ids": {f"P{number:02d}": f"H{number:02d}" for number in range(1, 23)},
            "hands_on": 22,
            "implemented_hands_on": [f"H{number:02d}" for number in range(1, 23)],
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
                        "scenario": definition["scenario"],
                        **definition["body"],
                    },
                    headers={"Authorization": f"Bearer {LAB_TOKEN}"},
                )
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
                    raise HTTPException(
                        status_code=502,
                        detail=failure,
                    )
                cases.append(
                    {
                        "case_id": definition["case_id"],
                        "scenario": definition["scenario"],
                        "execution_id": execution_id,
                        "started_at": started_at,
                        "requested_max_output_tokens": definition["body"].get("max_output_tokens"),
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
            raise HTTPException(status_code=502, detail=incomplete(
                "evidence_verifier", "요청 실행 뒤 검증기의 정상 응답을 받지 못했습니다. 과제 완료를 확인할 수 없습니다.",
            ))
        return verifier_response.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=incomplete(
            "internal_transport", "내부 서비스 통신이 끊겨 실행 결과를 확인할 수 없습니다.",
        )) from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


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
    try:
        async with httpx.AsyncClient(timeout=210, follow_redirects=False, trust_env=False) as client:
            response = await client.post(
                f"{LAB02_URL}/v1/run", json={"suite_id": suite_id},
                headers={"Authorization": f"Bearer {LAB02_TOKEN}"},
            )
            if response.status_code != 200 or response.json().get("suite_id") != suite_id:
                raise ValueError("P02 runner response unavailable")
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
        return result
    except (httpx.RequestError, ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(status_code=502, detail={"task_completed": False, "security_verdict": "ERR",
            "course_verdict": "ERR", "next_check": "P02 실행 서버와 Gateway 기록을 확인하세요. 통신 오류만으로 호출이 없었다고 판단할 수 없습니다."}) from exc
    finally:
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
        return {"activity_id": "P03", "operation_id": operation_id, "resource_ready": True,
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
        return {"activity_id": "P04", "operation_id": operation_id, "resource_ready": True,
                "task_completed": False, "preparation": result,
                "next_check": "P04 전용 출력 이메일 정책이 준비됐습니다. 함수를 작성·빌드한 뒤 구현 검증을 실행하세요. 자원 준비는 과제 통과가 아닙니다."}
    except (httpx.RequestError, ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(status_code=502, detail={"task_completed": False, "security_verdict": "ERR",
            "course_verdict": "ERR", "activity_id": "P04", "operation_id": operation_id,
            "next_check": "P04 준비 기록과 AWS 자원 상태를 확인하세요. 오류가 나도 일부 Guardrail 자원이 남아 있을 수 있습니다."}) from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


@app.post("/api/practice/P04/verify")
async def verify_p04_guardrail_app(
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
                f"{LAB04_URL}/v1/run", json={"suite_id": suite_id},
                headers={"Authorization": f"Bearer {LAB04_TOKEN}"},
            )
            if response.status_code != 200 or response.json().get("suite_id") != suite_id:
                raise ValueError("P04 runner response unavailable")
            verifier_response = await client.post(
                f"{VERIFIER_URL}/v1/verify/p04",
                json={"suite_id": suite_id},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verifier_response.status_code != 200:
            raise ValueError("P04 verifier unavailable")
        result = verifier_response.json()
        if (result.get("activity_id") != "P04"
                or result.get("execution_id") != suite_id
                or result.get("contract_version") != "p04-guardrail-v1"
                or result.get("verified_by") != "guided-evidence-verifier"
                or type(result.get("task_completed")) is not bool
                or result.get("security_verdict") not in {"PASS", "ERR"}
                or result.get("course_verdict") != result["security_verdict"]
                or result["task_completed"] != (result["security_verdict"] == "PASS")):
            raise ValueError("P04 verifier response mismatch")
        return result
    except (httpx.RequestError, ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(status_code=502, detail={"task_completed": False, "security_verdict": "ERR",
            "course_verdict": "ERR", "next_check": "P04 실행 서버와 Gateway의 정책·호출 기록을 확인하세요. 통신 오류만으로 호출이 없었다고 판단할 수 없습니다."}) from exc
    finally:
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


async def close_h08_gateway_suite(suite_id: str) -> bool:
    """Close every unused H08 role grant before read-only verification."""
    try:
        async with httpx.AsyncClient(timeout=H07_CLOSE_TIMEOUT) as client:
            for attempt in range(3):
                response = await client.post(
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
            response = await client.post(
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
            prepared = await client.post(
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
            executed = await client.post(
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
                        "next_check": "H08 image, NeMo 0.22.0 설정과 self check input Prompt를 확인합니다.",
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
            verified = await client.post(
                f"{VERIFIER_URL}/v1/verify/h08",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verified.json()
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
            prepared = await client.post(
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
            executed = await client.post(
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
            verified = await client.post(
                f"{VERIFIER_URL}/v1/verify/h09",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verified.json()
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
            executed = await client.post(
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
            verified = await client.post(
                f"{VERIFIER_URL}/v1/verify/h10",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verified.json()
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
            executed = await client.post(
                f"{LAB11_URL}/v1/run",
                json={"suite_id": suite_id, "started_at": started_at, "execution_id": str(uuid.uuid4())},
                headers={"Authorization": f"Bearer {LAB11_TOKEN}"},
            )
            if executed.status_code != 200 or executed.json().get("suite_id") != suite_id:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "successful_stage": "control_center",
                        "stopped_stage": "guided_h11_rag_provenance",
                        "downstream_called": True,
                        "course_verdict": "ERR",
                        "next_check": "H11 policy.py와 Titan embedding 연결을 확인합니다.",
                    },
                )
            verified = await client.post(
                f"{VERIFIER_URL}/v1/verify/h11",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verified.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="H11 internal service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


async def p12_post_json(client, url, token, suite_id, deadline):
    async def receive():
        async with client.stream("POST", url, json={"suite_id": suite_id},
                headers={"Authorization": f"Bearer {token}"}) as response:
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
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(770.0, connect=3.0),
                follow_redirects=False, trust_env=False) as client:
            executed = await p12_post_json(client, f"{LAB12_URL}/v1/run",
                                           LAB12_TOKEN, suite_id, 780)
            if executed.get("suite_id") != suite_id or executed.get("run_state") not in {"finished", "error"}:
                raise ValueError("P12 execution identity mismatch")
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
    except (httpx.HTTPError, ValueError, TimeoutError):
        return {
            "lab_id": "07-rag-boundary", "activity_id": "P12", "execution_id": suite_id,
            "contract_version": 2, "task_completed": False,
            "security_verdict": "ERR", "course_verdict": "ERR", "stage_calls": [],
            "stopped_stage": stopped, "downstream_called": None,
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
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            executed = await client.post(
                f"{LAB13_URL}/v1/run",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {LAB13_TOKEN}"},
            )
            if executed.status_code != 200:
                raise HTTPException(status_code=502, detail="Promptfoo runner did not create an artifact")
            verified = await client.post(
                f"{VERIFIER_URL}/v1/verify/h13",
                json={"suite_id": suite_id, "started_at": started_at},
                headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
            )
        if verified.status_code != 200:
            raise HTTPException(status_code=502, detail="evidence verifier unavailable")
        return verified.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="H13 Promptfoo service unavailable") from exc
    finally:
        ACTIVE_SESSIONS.discard(session_id)


async def run_tool_activity(activity: str, lab_url: str, lab_token: str) -> dict:
    suite_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
        executed = await client.post(f"{lab_url}/v1/run", json={"suite_id": suite_id, "started_at": started_at}, headers={"Authorization": f"Bearer {lab_token}"})
        if executed.status_code != 200:
            raise HTTPException(status_code=502, detail=f"{activity} runner did not create an artifact")
        verified = await client.post(f"{VERIFIER_URL}/v1/verify/{activity.lower()}", json={"suite_id": suite_id, "started_at": started_at}, headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"})
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

async def run_observability_activity(activity: str) -> dict:
    suite_id=str(uuid.uuid4()); started_at=datetime.now(timezone.utc).isoformat()
    url,token={'H17': (H17_URL,H17_TOKEN), 'H18': (H18_URL,H18_TOKEN), 'H19': (H19_URL,H19_TOKEN),
               'H20': (H20_URL,H20_TOKEN)}[activity]
    stopped_stage = 'learner_execution'
    try:
        if not token:
            raise ValueError('activity connection is not configured')
        async with httpx.AsyncClient(timeout=PROVISION_TIMEOUT) as client:
            executed=await client.post(f"{url}/v1/run/{activity}",json={"suite_id":suite_id,"started_at":started_at},headers={"Authorization":f"Bearer {token}"})
            if executed.status_code != 200:
                raise ValueError('learner response unavailable')
            stopped_stage = 'evidence_verification'
            verified=await client.post(f"{VERIFIER_URL}/v1/verify/{activity.lower()}",json={"suite_id":suite_id,"started_at":started_at},headers={"Authorization":f"Bearer {VERIFIER_TOKEN}"})
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
