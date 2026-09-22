"""03 테넌트용 UI와 기존 Application API를 잇는 얇은 Python 서비스."""

from __future__ import annotations

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

app = FastAPI(title="LLM Security Guided Control Center", version=APP_VERSION)


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    """학습 화면만 제공하며 보안 판정은 기존 Application이 수행한다."""
    html = INDEX.read_text(encoding="utf-8").replace("__APP_VERSION__", APP_VERSION)
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "guided-control-center", "version": APP_VERSION}


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
