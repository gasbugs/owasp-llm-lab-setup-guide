"""Learner-owned H04 app that compares standalone and connected Guardrails."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from pathlib import Path
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field


GATEWAY_URL = os.getenv("GUIDED_BEDROCK_GATEWAY_URL", "http://guided-bedrock-gateway:8080")
SERVICE_TOKEN = os.environ["GUIDED_H04_GATEWAY_TOKEN"]
CONTROL_TOKEN = os.environ["GUIDED_CONTROL_LAB04_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_LAB04_TOKEN"]
DATABASE_PATH = os.getenv("GUIDED_H04_DATABASE", "/tmp/h04-receipts.sqlite3")

# Starter는 단독 검사만 실행하고 실제 Converse에는 Guardrail을 붙이지 않습니다.
# TODO(H04): 같은 H04 Guardrail을 Nova Lite 호출에도 연결하도록 True로 바꿉니다.
USE_GUARDRAIL_FOR_CONVERSE = False

Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        "CREATE TABLE IF NOT EXISTS receipts "
        "(execution_id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL)"
    )


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    case_id: Literal[
        "apply-normal", "apply-risk", "converse-normal", "converse-risk"
    ]


def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_control(authorization: str | None = Header(default=None)) -> None:
    bearer(CONTROL_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


def source_digest() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def run(request: RunRequest) -> dict:
    operation = "apply" if request.case_id.startswith("apply-") else "converse"
    payload = request.model_dump()
    if operation == "converse":
        payload["attach_guardrail"] = USE_GUARDRAIL_FOR_CONVERSE
    response = httpx.post(
        f"{GATEWAY_URL}/v1/h04/{operation}",
        json=payload,
        headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
        timeout=60.0,
    )
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail=f"H04 {operation} failed")
    provider = response.json()
    receipt = {
        "execution_id": request.execution_id,
        "started_at": request.started_at,
        "case_id": request.case_id,
        "source_digest": source_digest(),
        "gateway_evidence_id": request.execution_id,
        "operation": operation,
        "attach_guardrail": (
            USE_GUARDRAIL_FOR_CONVERSE if operation == "converse" else None
        ),
        "provider_request_id": provider["provider_request_id"],
    }
    with connect() as database:
        database.execute(
            "INSERT INTO receipts VALUES(?,?)",
            (request.execution_id, json.dumps(receipt, ensure_ascii=False)),
        )
    return receipt


app = FastAPI(title="Tenant 03 H04 Guardrail App", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    with connect() as database:
        database.execute("SELECT 1").fetchone()
    return {"status": "ready", "provider_check": "not-run"}


@app.post("/v1/run")
def run_case(request: RunRequest, _authorized: None = Depends(require_control)) -> dict:
    try:
        return run(request)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="Bedrock Gateway unavailable") from exc


@app.get("/v1/build-info")
def build_info(_authorized: None = Depends(require_verifier)) -> dict[str, str]:
    return {"component": "guided-h04-guardrail-app", "source_digest": source_digest()}


@app.get("/v1/receipts/{execution_id}")
def receipt(execution_id: str, _authorized: None = Depends(require_verifier)) -> dict:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM receipts WHERE execution_id=?", (execution_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="receipt not found")
    return json.loads(row["receipt_json"])
