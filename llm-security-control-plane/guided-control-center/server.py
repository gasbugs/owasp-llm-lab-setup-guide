"""03 테넌트용 UI와 기존 Application API를 잇는 얇은 Python 서비스."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

APP_VERSION = os.getenv("RELEASE_VERSION", os.getenv("APP_VERSION", "dev"))
APPLICATION_URL = os.getenv(
    "APPLICATION_URL", "http://llm-security-application-gateway:8000"
).rstrip("/")
INDEX = Path(__file__).with_name("index.html")
TIMEOUT = httpx.Timeout(370.0, connect=5.0)
OFFICIAL_UI_TIMEOUT = httpx.Timeout(2.0, connect=1.0)

OFFICIAL_UIS = (
    {
        "id": "nemo",
        "name": "NeMo Chat UI",
        "purpose": "Dialog Rail을 대화로 직접 확인",
        "browser_url": os.getenv(
            "NEMO_OFFICIAL_UI_BROWSER_URL", "http://127.0.0.1:18192"
        ),
        "health_url": os.getenv(
            "NEMO_OFFICIAL_UI_HEALTH_URL",
            "http://llm-security-nemo-official-ui:8000/v1/rails/configs",
        ),
        "boundary": "NeMo 단독 Rail 화면이며 Application 통합 판정은 Control Center에서 확인",
    },
    {
        "id": "promptfoo",
        "name": "Promptfoo Viewer",
        "purpose": "정상·공격 회귀 결과를 표와 필터로 비교",
        "browser_url": os.getenv(
            "PROMPTFOO_UI_BROWSER_URL", "http://127.0.0.1:15500"
        ),
        "health_url": os.getenv(
            "PROMPTFOO_UI_HEALTH_URL",
            "http://llm-security-promptfoo-official-ui:15500/",
        ),
        "boundary": "평가 결과 Viewer이며 운영 정책을 직접 바꾸지 않음",
    },
    {
        "id": "pyrit",
        "name": "CoPyRIT",
        "purpose": "적응형 공격의 턴과 Scorer를 탐색",
        "browser_url": os.getenv(
            "PYRIT_UI_BROWSER_URL", "http://127.0.0.1:18098"
        ),
        "health_url": os.getenv(
            "PYRIT_UI_HEALTH_URL", "http://llm-security-pyrit-official-ui:8000/"
        ),
        "boundary": "인증 기능이 없으므로 loopback에서만 사용하는 개인 실습 화면",
    },
    {
        "id": "grafana",
        "name": "Grafana Explore",
        "purpose": "Log·Trace·Metric 원본과 Dashboard를 연결",
        "browser_url": os.getenv(
            "GRAFANA_BROWSER_URL", "http://127.0.0.1:3001/explore"
        ),
        "health_url": os.getenv(
            "GRAFANA_HEALTH_URL", "http://llm-sec-grafana:3000/api/health"
        ),
        "boundary": "관측 화면이며 인증·인가와 보안 집행을 대신하지 않음",
    },
)

EXTERNAL_OFFICIAL_UIS = (
    {
        "id": "bedrock-guardrails",
        "name": "Bedrock Guardrails Console",
        "purpose": "Guardrail 정책과 Test 창 확인",
        "browser_url": "https://console.aws.amazon.com/bedrock/home?region=us-east-1#/guardrails",
        "boundary": "AWS Console 로그인과 수강생 본인 계정 권한을 사용",
        "status": "external",
    },
    {
        "id": "bedrock-knowledge-bases",
        "name": "Bedrock Knowledge Bases Console",
        "purpose": "검색 결과와 출처를 AWS 화면에서 확인",
        "browser_url": "https://console.aws.amazon.com/bedrock/home?region=us-east-1#/knowledge-bases",
        "boundary": "Application 인가 뒤의 AWS 검색 상태를 보는 화면",
        "status": "external",
    },
)

app = FastAPI(title="LLM Security Guided Control Center", version=APP_VERSION)


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    """학습 화면만 제공하며 보안 판정은 기존 Application이 수행한다."""
    html = INDEX.read_text(encoding="utf-8").replace("__APP_VERSION__", APP_VERSION)
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "guided-control-center", "version": APP_VERSION}


async def _official_ui_status(
    client: httpx.AsyncClient, item: dict[str, str]
) -> dict[str, str]:
    """내부 주소는 상태 확인에만 쓰고 Browser에는 공개 주소만 돌려준다."""
    status = "unavailable"
    try:
        response = await client.get(item["health_url"])
        if response.status_code < 400:
            status = "ready"
    except httpx.RequestError:
        pass
    return {key: value for key, value in item.items() if key != "health_url"} | {
        "status": status
    }


@app.get("/api/official-uis")
async def official_uis() -> dict[str, list[dict[str, str]]]:
    """제품이 제공하는 공식 화면과 현재 기동 상태를 학습 UI에 전달한다."""
    async with httpx.AsyncClient(timeout=OFFICIAL_UI_TIMEOUT) as client:
        local = await asyncio.gather(
            *(_official_ui_status(client, item) for item in OFFICIAL_UIS)
        )
    return {"items": [*local, *EXTERNAL_OFFICIAL_UIS]}


async def _proxy(
    path: str, request: Request, authorization: str | None = None
) -> JSONResponse:
    """Browser 입력을 Application에 전달하고 원문 상태·JSON을 보존한다."""
    try:
        payload: Any = await request.json()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="JSON body가 필요합니다.") from exc

    headers = {"content-type": "application/json"}
    if authorization:
        headers["authorization"] = authorization

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(
                f"{APPLICATION_URL}{path}", json=payload, headers=headers
            )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail="Application에 연결하지 못했습니다. 실행 상태를 확인하세요.",
        ) from exc

    try:
        body = response.json()
    except ValueError:
        body = {"detail": response.text or "Application이 JSON을 반환하지 않았습니다."}
    return JSONResponse(status_code=response.status_code, content=body)


@app.post("/.well-known/login")
async def login(request: Request) -> JSONResponse:
    return await _proxy("/.well-known/login", request)


@app.post("/api/chat")
async def chat(
    request: Request, authorization: str | None = Header(default=None)
) -> JSONResponse:
    return await _proxy("/api/chat", request, authorization)
