"""Learner-owned H02 document preparation application."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field


GATEWAY_URL = os.getenv("GUIDED_BEDROCK_GATEWAY_URL", "http://guided-bedrock-gateway:8080")
SERVICE_AUTH_TOKEN = os.environ["GUIDED_H02_GATEWAY_TOKEN"]
CONTROL_TOKEN = os.environ["GUIDED_CONTROL_LAB02_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_LAB02_TOKEN"]
DATABASE_PATH = os.getenv("GUIDED_H02_DATABASE", "/tmp/h02-receipts.sqlite3")

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


class DocumentRequest(BaseModel):
    # TODO(H02): 계약에 없는 object_key를 HTTP 422로 거부하도록 바꾼다.
    model_config = ConfigDict(extra="allow")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    title: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=10, max_length=4000)
    scenario: Literal["normal", "risk"]


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


def save_receipt(receipt: dict) -> None:
    with connect() as database:
        database.execute(
            "INSERT INTO receipts VALUES(?,?)",
            (receipt["execution_id"], json.dumps(receipt, ensure_ascii=False)),
        )


def prepare_document(request: DocumentRequest) -> dict:
    """Starter: a client-supplied object key crosses the application boundary."""
    extra_key = (request.model_extra or {}).get("object_key")
    object_key = (
        extra_key
        if isinstance(extra_key, str)
        else f"h02/knowledge/{request.execution_id}.md"
    )
    response = httpx.post(
        f"{GATEWAY_URL}/v1/h02/documents",
        json={
            "execution_id": request.execution_id,
            "started_at": request.started_at,
            "title": request.title,
            "body": request.body,
            "object_key": object_key,
            "scenario": request.scenario,
        },
        headers={"Authorization": f"Bearer {SERVICE_AUTH_TOKEN}"},
        timeout=30.0,
    )
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="Bedrock Gateway document call failed")
    gateway_receipt = response.json()
    receipt = {
        "execution_id": request.execution_id,
        "started_at": request.started_at,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "scenario": request.scenario,
        "source_digest": source_digest(),
        "object_key": object_key,
        "gateway_evidence_id": gateway_receipt["execution_id"],
        "upstream_called": True,
    }
    save_receipt(receipt)
    return {**receipt, "result": gateway_receipt}


app = FastAPI(title="Tenant 03 H02 Document App", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    with connect() as database:
        database.execute("SELECT 1").fetchone()
    return {"status": "ready", "provider_check": "not-run"}


@app.post("/v1/documents")
def documents(
    request: DocumentRequest, _authorized: None = Depends(require_control)
) -> dict:
    try:
        return prepare_document(request)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="Bedrock Gateway unavailable") from exc


@app.get("/v1/build-info")
def build_info(_authorized: None = Depends(require_verifier)) -> dict[str, str]:
    return {"component": "guided-h02-document-app", "source_digest": source_digest()}


@app.get("/v1/receipts/{execution_id}")
def receipt(execution_id: str, _authorized: None = Depends(require_verifier)) -> dict:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM receipts WHERE execution_id=?", (execution_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="receipt not found")
    return json.loads(row["receipt_json"])
