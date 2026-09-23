"""Learner-owned H01 Bedrock Gateway and its read-only evidence endpoint."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field


MODEL_ID = "us.amazon.nova-lite-v1:0"
REGION = "us-east-1"
CONTROL_TOKEN = os.environ["GUIDED_CONTROL_LAB01_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_LAB01_TOKEN"]
PROVIDER_MODE = os.getenv("GUIDED_PROVIDER_MODE", "aws")
DATABASE_PATH = os.getenv("GUIDED_LAB01_DATABASE", "/tmp/receipts.sqlite3")
SOURCE_PATH = Path("/app/server.py")

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


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    message: str = Field(min_length=1, max_length=4000)
    max_output_tokens: int = Field(ge=1, le=512)
    scenario: Literal["normal", "risk", "preflight", "chat"]


def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_control(authorization: str | None = Header(default=None)) -> None:
    bearer(CONTROL_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


def source_digest() -> str:
    return hashlib.sha256(SOURCE_PATH.read_bytes()).hexdigest()


def save_receipt(receipt: dict) -> None:
    try:
        with connect() as database:
            database.execute(
                "INSERT INTO receipts VALUES(?,?)",
                (receipt["execution_id"], json.dumps(receipt, ensure_ascii=False)),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="execution ID already exists") from exc


def call_nova(message: str, max_tokens: int, execution_id: str) -> dict:
    if PROVIDER_MODE == "contract":
        request_id = hashlib.sha256(f"{execution_id}:{message}:{max_tokens}".encode()).hexdigest()[:24]
        output_tokens = max_tokens if "GUIDED-H01-RISK" in message else min(max_tokens, 32)
        return {
            "request_id": f"contract-{request_id}",
            "text": "계약 테스트용 Nova Lite 응답입니다.",
            "stop_reason": "max_tokens" if output_tokens == max_tokens else "end_turn",
            "usage": {"inputTokens": 12, "outputTokens": output_tokens, "totalTokens": 12 + output_tokens},
            "provider_mode": "contract",
        }

    try:
        result = boto3.client("bedrock-runtime", region_name=REGION).converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [{"text": message}]}],
            inferenceConfig={"maxTokens": max_tokens, "temperature": 0.0},
        )
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(status_code=502, detail=f"Bedrock Converse failed: {type(exc).__name__}") from exc

    request_id = result.get("ResponseMetadata", {}).get("RequestId")
    usage = result.get("usage")
    if not request_id or not isinstance(usage, dict):
        raise HTTPException(status_code=502, detail="Bedrock evidence is incomplete")
    text = "".join(
        part.get("text", "")
        for part in result.get("output", {}).get("message", {}).get("content", [])
    )
    return {
        "request_id": request_id,
        "text": text,
        "stop_reason": result.get("stopReason", "unknown"),
        "usage": usage,
        "provider_mode": "aws",
    }


app = FastAPI(title="H01 Learner Bedrock Gateway", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    with connect() as database:
        database.execute("SELECT 1").fetchone()
    return {"status": "ready", "provider_check": "not-run"}


@app.post("/v1/chat")
def chat(request: ChatRequest, _authorized: None = Depends(require_control)) -> dict:
    # TODO(H01): 큰 요청을 128 이하로 제한한다. Starter는 의도적으로 그대로 전달한다.
    effective_max_tokens = request.max_output_tokens
    provider = call_nova(request.message, effective_max_tokens, request.execution_id)
    observed_at = datetime.now(timezone.utc).isoformat()
    receipt = {
        "execution_id": request.execution_id,
        "started_at": request.started_at,
        "observed_at": observed_at,
        "scenario": request.scenario,
        "requested_max_output_tokens": request.max_output_tokens,
        "effective_max_output_tokens": effective_max_tokens,
        "source_digest": source_digest(),
        "provider_request_id": provider["request_id"],
        "provider_mode": provider["provider_mode"],
        "model_id": MODEL_ID,
        "region": REGION,
        "forwarded_parameters": {"maxTokens": effective_max_tokens, "temperature": 0.0},
        "usage": provider["usage"],
        "stop_reason": provider["stop_reason"],
        "response_text": provider["text"],
        "upstream_called": True,
    }
    save_receipt(receipt)
    return receipt


@app.get("/v1/build-info")
def build_info(_authorized: None = Depends(require_verifier)) -> dict[str, str]:
    return {"component": "guided-h01-gateway", "source_digest": source_digest()}


@app.get("/v1/receipts/{execution_id}")
def receipt(execution_id: str, _authorized: None = Depends(require_verifier)) -> dict:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM receipts WHERE execution_id=?", (execution_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="receipt not found")
    return json.loads(row["receipt_json"])
