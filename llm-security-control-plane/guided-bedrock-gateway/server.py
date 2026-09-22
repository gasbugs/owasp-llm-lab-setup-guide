"""Credential boundary and immutable evidence ledger for tenant 03."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field


MODEL_ID = "us.amazon.nova-lite-v1:0"
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
PROVIDER_MODE = os.getenv("GUIDED_PROVIDER_MODE", "aws")
DATABASE_PATH = os.getenv("GUIDED_GATEWAY_DATABASE", "/state/evidence.sqlite3")
LAB01_TOKEN = os.environ["GUIDED_LAB01_GATEWAY_TOKEN"]
NEMO_TOKEN = os.environ["GUIDED_NEMO_GATEWAY_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_GATEWAY_TOKEN"]

Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        """CREATE TABLE IF NOT EXISTS evidence (
        execution_id TEXT PRIMARY KEY,
        provider_request_id TEXT NOT NULL UNIQUE,
        observed_at TEXT NOT NULL,
        receipt_json TEXT NOT NULL
        )"""
    )


class InvokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    prompt: str = Field(min_length=1, max_length=4000)
    max_output_tokens: int = Field(ge=1, le=512)
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=4000)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    model: str
    messages: list[ChatMessage] = Field(min_length=1, max_length=20)
    max_tokens: int = Field(default=180, ge=1, le=512)
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    stream: bool = False


def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_lab01(authorization: str | None = Header(default=None)) -> None:
    bearer(LAB01_TOKEN, authorization)


def require_nemo(authorization: str | None = Header(default=None)) -> None:
    bearer(NEMO_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


def config_digest(max_output_tokens: int, temperature: float) -> str:
    payload = {
        "model_id": MODEL_ID,
        "inference_config": {
            "maxTokens": max_output_tokens,
            "temperature": temperature,
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def call_provider(
    prompt: str, max_output_tokens: int, temperature: float, request_identity: str
) -> dict:
    if PROVIDER_MODE == "contract":
        request_id = hashlib.sha256(
            f"{request_identity}:{prompt}:{max_output_tokens}:{temperature}".encode()
        ).hexdigest()[:24]
        if "XSS-REGRESSION" in prompt:
            text = '<img src=x onerror="window.__guided_xss=true"><script>window.__guided_xss=true</script>'
        else:
            text = "계약 테스트 응답입니다. " + ("안전한 출력 상한을 확인했습니다. " * 8)
        # The fixed risk probe must consume the forwarded allowance so an
        # unbounded starter is deterministically distinguishable from a fix.
        output_tokens = (
            max_output_tokens
            if "GUIDED-H01-RISK" in prompt
            else min(max_output_tokens, 48)
        )
        return {
            "request_id": f"contract-{request_id}",
            "text": text,
            "stop_reason": "max_tokens" if output_tokens == max_output_tokens else "end_turn",
            "usage": {
                "inputTokens": 18,
                "outputTokens": output_tokens,
                "totalTokens": 18 + output_tokens,
            },
            "provider_mode": "contract",
        }

    try:
        result = boto3.client("bedrock-runtime", region_name=AWS_REGION).converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={
                "maxTokens": max_output_tokens,
                "temperature": temperature,
            },
        )
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(
            status_code=502, detail=f"Bedrock Converse failed: {type(exc).__name__}"
        ) from exc

    request_id = result.get("ResponseMetadata", {}).get("RequestId")
    if not request_id:
        raise HTTPException(status_code=502, detail="provider request ID is missing")
    usage = result.get("usage")
    if not isinstance(usage, dict) or any(
        type(usage.get(field)) is not int
        for field in ("inputTokens", "outputTokens", "totalTokens")
    ):
        raise HTTPException(status_code=502, detail="provider usage is missing")
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


def invoke_once(request: InvokeRequest) -> dict:
    with connect() as database:
        if database.execute(
            "SELECT 1 FROM evidence WHERE execution_id=?", (request.execution_id,)
        ).fetchone():
            raise HTTPException(status_code=409, detail="execution ID already exists")

    provider = call_provider(
        request.prompt,
        request.max_output_tokens,
        request.temperature,
        request.execution_id,
    )
    observed_at = datetime.now(timezone.utc).isoformat()
    digest = config_digest(request.max_output_tokens, request.temperature)
    receipt = {
        "execution_id": request.execution_id,
        "provider_request_id": provider["request_id"],
        "provider_mode": provider["provider_mode"],
        "observed_at": observed_at,
        "model_id": MODEL_ID,
        "region": AWS_REGION,
        "forwarded_parameters": {
            "maxTokens": request.max_output_tokens,
            "temperature": request.temperature,
        },
        "usage": provider["usage"],
        "stop_reason": provider["stop_reason"],
        "output_text": provider["text"],
        "config_digest": digest,
    }
    try:
        with connect() as database:
            database.execute(
                "INSERT INTO evidence VALUES(?,?,?,?)",
                (
                    request.execution_id,
                    provider["request_id"],
                    observed_at,
                    json.dumps(receipt, ensure_ascii=False),
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="provider evidence already used") from exc
    return receipt


app = FastAPI(title="Tenant 03 Bedrock Gateway", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    with connect() as database:
        database.execute("SELECT 1").fetchone()
    return {"status": "ready", "provider_check": "not-run"}


@app.post("/v1/nova/invoke")
def invoke(request: InvokeRequest, _authorized: None = Depends(require_lab01)) -> dict:
    return invoke_once(request)


@app.post("/v1/provider-preflight")
def provider_preflight(
    request: InvokeRequest, _authorized: None = Depends(require_lab01)
) -> dict:
    if request.max_output_tokens > 2:
        raise HTTPException(status_code=422, detail="preflight max output is 2")
    return invoke_once(request)


@app.get("/v1/evidence/{execution_id}")
def evidence(
    execution_id: str, _authorized: None = Depends(require_verifier)
) -> dict:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM evidence WHERE execution_id=?", (execution_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    return json.loads(row["receipt_json"])


@app.post("/v1/chat/completions")
def chat(request: ChatRequest, _authorized: None = Depends(require_nemo)) -> dict:
    if request.stream:
        raise HTTPException(status_code=422, detail="streaming is not enabled")
    prompt = "\n".join(message.content for message in request.messages)
    provider = call_provider(prompt, request.max_tokens, request.temperature, str(uuid.uuid4()))
    return {
        "id": provider["request_id"],
        "object": "chat.completion",
        "model": MODEL_ID,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": provider["text"]},
                "finish_reason": "length"
                if provider["stop_reason"] == "max_tokens"
                else "stop",
            }
        ],
        "usage": {
            "prompt_tokens": provider["usage"]["inputTokens"],
            "completion_tokens": provider["usage"]["outputTokens"],
            "total_tokens": provider["usage"]["totalTokens"],
        },
    }
