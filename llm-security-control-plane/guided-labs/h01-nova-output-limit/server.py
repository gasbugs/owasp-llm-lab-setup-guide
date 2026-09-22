"""Learner-owned H01 application; it never assigns the course verdict."""

from __future__ import annotations

import hmac
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from policy import apply_output_limit


GATEWAY_URL = os.getenv("GUIDED_BEDROCK_GATEWAY_URL", "http://guided-bedrock-gateway:8080")
CONTROL_TOKEN = os.environ["GUIDED_CONTROL_LAB01_TOKEN"]
GATEWAY_TOKEN = os.environ["GUIDED_LAB01_GATEWAY_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_LAB01_TOKEN"]
DATABASE_PATH = os.getenv("GUIDED_LAB01_DATABASE", "/state/receipts.sqlite3")

Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        """CREATE TABLE IF NOT EXISTS receipts (
        execution_id TEXT PRIMARY KEY,
        receipt_json TEXT NOT NULL
        )"""
    )


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    prompt: str = Field(min_length=1, max_length=4000)
    requested_max_output_tokens: int = Field(ge=1, le=512)
    scenario: Literal["normal", "risk", "preflight", "chat"]


def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_control(authorization: str | None = Header(default=None)) -> None:
    bearer(CONTROL_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


app = FastAPI(title="Tenant 03 Learner App", docs_url=None, redoc_url=None)


def policy_digest() -> str:
    return hashlib.sha256(Path("/app/policy.py").read_bytes()).hexdigest()


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    with connect() as database:
        database.execute("SELECT 1").fetchone()
    return {"status": "ready", "lab_ready": "true"}


@app.post("/v1/run")
def run(request: RunRequest, _authorized: None = Depends(require_control)) -> dict:
    effective_max_tokens = apply_output_limit(request.requested_max_output_tokens)
    if type(effective_max_tokens) is not int or not 1 <= effective_max_tokens <= 512:
        raise HTTPException(status_code=500, detail="output policy returned an invalid limit")
    endpoint = "/v1/provider-preflight" if request.scenario == "preflight" else "/v1/nova/invoke"
    payload = {
        "execution_id": request.execution_id,
        "prompt": request.prompt,
        "max_output_tokens": effective_max_tokens,
        "temperature": 0.0,
    }
    try:
        response = httpx.post(
            f"{GATEWAY_URL}{endpoint}",
            json=payload,
            headers={"Authorization": f"Bearer {GATEWAY_TOKEN}"},
            timeout=120.0,
        )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="Bedrock Gateway unavailable") from exc
    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail={"gateway_status": response.status_code, "gateway_body": response.text[:400]},
        )
    provider = response.json()
    receipt = {
        "execution_id": request.execution_id,
        "started_at": request.started_at,
        "completed": True,
        "scenario": request.scenario,
        "requested_max_output_tokens": request.requested_max_output_tokens,
        "effective_max_output_tokens": effective_max_tokens,
        "policy_digest": policy_digest(),
        "config_digest": provider["config_digest"],
        "provider_request_id": provider["provider_request_id"],
    }
    try:
        with connect() as database:
            database.execute(
                "INSERT INTO receipts VALUES(?,?)",
                (request.execution_id, json.dumps(receipt, ensure_ascii=False)),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="execution ID already exists") from exc
    return {
        **receipt,
        "model_id": provider["model_id"],
        "forwarded_parameters": provider["forwarded_parameters"],
        "usage": provider["usage"],
        "stop_reason": provider["stop_reason"],
        "response_text": provider["output_text"],
    }


@app.get("/v1/build-info")
def build_info(_authorized: None = Depends(require_verifier)) -> dict[str, str]:
    return {"component": "guided-student-app", "policy_digest": policy_digest()}


@app.get("/v1/receipts/{execution_id}")
def receipt(
    execution_id: str, _authorized: None = Depends(require_verifier)
) -> dict:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM receipts WHERE execution_id=?", (execution_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="receipt not found")
    return json.loads(row["receipt_json"])
