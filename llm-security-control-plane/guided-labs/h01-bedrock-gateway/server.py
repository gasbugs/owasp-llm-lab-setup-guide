"""Learner-owned H01 Bedrock Gateway and its read-only evidence endpoint."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

import learner
from provider import InvocationError, RecordingClient


MODEL_ID = "us.amazon.nova-lite-v1:0"
REGION = "us-east-1"
CONTROL_TOKEN = os.environ["GUIDED_CONTROL_LAB01_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_LAB01_TOKEN"]
PROVIDER_MODE = os.getenv("GUIDED_PROVIDER_MODE", "aws")
DATABASE_PATH = os.getenv("GUIDED_LAB01_DATABASE", "/tmp/receipts.sqlite3")
SOURCE_PATH = Path(__file__).resolve()

Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def connect():
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    try:
        with database:
            yield database
    finally:
        database.close()


with connect() as database:
    database.execute(
        "CREATE TABLE IF NOT EXISTS receipts "
        "(execution_id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL)"
    )
    database.execute(
        "CREATE TABLE IF NOT EXISTS executions "
        "(execution_id TEXT PRIMARY KEY, record_json TEXT NOT NULL)"
    )


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
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
    digest = hashlib.sha256()
    for name in ("server.py", "learner.py", "provider.py"):
        digest.update(name.encode() + b"\0" + SOURCE_PATH.with_name(name).read_bytes() + b"\0")
    return digest.hexdigest()


def runner_digests() -> dict[str, str]:
    return {name: hashlib.sha256(SOURCE_PATH.with_name(name).read_bytes()).hexdigest()
            for name in ("server.py", "provider.py")}


def save_receipt(receipt: dict) -> None:
    try:
        with connect() as database:
            database.execute(
                "INSERT INTO receipts VALUES(?,?)",
                (receipt["execution_id"], json.dumps(receipt, ensure_ascii=False)),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="execution ID already exists") from exc


def begin_execution(request: ChatRequest) -> dict:
    record = {
        "execution_id": request.execution_id, "started_at": request.started_at,
        "scenario": request.scenario, "source_digest": source_digest(),
        "runner_digests": runner_digests(),
        "activity_id": "P01", "internal_activity_id": "H01", "contract_version": 2,
        "closed": False, "provider_mode": PROVIDER_MODE,
        "request_digest": hashlib.sha256(json.dumps(request.model_extra or {}, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest(),
    }
    try:
        with connect() as database:
            database.execute("BEGIN IMMEDIATE")
            if database.execute("SELECT 1 FROM receipts WHERE execution_id=?", (request.execution_id,)).fetchone():
                raise HTTPException(status_code=409, detail="execution ID already exists")
            database.execute("INSERT INTO executions VALUES (?, ?)", (request.execution_id, json.dumps(record)))
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="execution ID already exists") from exc
    return record


def close_execution(record: dict, recorder: RecordingClient, status: int) -> None:
    record.update(
        closed=True, http_status=status, observed_at=datetime.now(timezone.utc).isoformat(),
        invocation_attempts=recorder.attempts, provider_attempts=recorder.provider_attempts,
        provider_results=len(recorder.results),
        provider_request_ids=[item.get("ResponseMetadata", {}).get("RequestId") for item in recorder.results],
    )
    with connect() as database:
        database.execute("UPDATE executions SET record_json=? WHERE execution_id=?", (json.dumps(record), record["execution_id"]))


app = FastAPI(title="P01 Learner Bedrock Gateway", docs_url=None, redoc_url=None)


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
    body = dict(request.model_extra or {})
    if PROVIDER_MODE not in {"contract", "aws"}:
        raise HTTPException(status_code=503, detail="unsupported provider mode")
    record = begin_execution(request)
    recorder = RecordingClient(
        request.execution_id,
        sdk_client_factory=(lambda: boto3.client("bedrock-runtime", region_name=REGION)) if PROVIDER_MODE == "aws" else None,
    )
    try:
        result = recorder.observed_result(learner.handle_request(body, recorder))
    except NotImplementedError as exc:
        status = 502 if recorder.attempts else 501
        close_execution(record, recorder, status)
        raise HTTPException(status_code=status, detail="P01 implementation is incomplete") from exc
    except ValueError as exc:
        close_execution(record, recorder, 502 if recorder.attempts else 422)
        if recorder.attempts:
            raise HTTPException(status_code=502, detail="request rejected after provider invocation") from exc
        raise HTTPException(status_code=422, detail="invalid chat request") from exc
    except (BotoCoreError, ClientError, InvocationError) as exc:
        close_execution(record, recorder, 502)
        raise HTTPException(status_code=502, detail="provider invocation failed or evidence is incomplete") from exc
    except Exception as exc:
        close_execution(record, recorder, 502)
        raise HTTPException(status_code=502, detail="learner implementation failed") from exc
    forwarded = recorder.calls[0]
    effective_max_tokens = forwarded["inferenceConfig"]["maxTokens"]
    observed_at = datetime.now(timezone.utc).isoformat()
    receipt = {
        "execution_id": request.execution_id,
        "started_at": request.started_at,
        "observed_at": observed_at,
        "scenario": request.scenario,
        "requested_max_output_tokens": body.get("max_output_tokens"),
        "effective_max_output_tokens": effective_max_tokens,
        "source_digest": record["source_digest"],
        "runner_digests": record["runner_digests"],
        "provider_request_id": result["ResponseMetadata"]["RequestId"],
        "provider_mode": PROVIDER_MODE,
        "model_id": forwarded.get("modelId"),
        "region": REGION,
        "forwarded_parameters": forwarded.get("inferenceConfig"),
        "forwarded_messages": forwarded.get("messages"),
        "usage": result["usage"],
        "stop_reason": result.get("stopReason", "unknown"),
        "response_text": "".join(part.get("text", "") for part in result.get("output", {}).get("message", {}).get("content", [])),
        "activity_id": "P01",
        "internal_activity_id": "H01",
        "contract_version": 2,
        "upstream_called": True,
    }
    save_receipt(receipt)
    close_execution(record, recorder, 200)
    return receipt


@app.get("/v1/build-info")
def build_info(_authorized: None = Depends(require_verifier)) -> dict:
    return {"component": "guided-h01-gateway", "source_digest": source_digest(),
            "runner_digests": runner_digests()}


@app.get("/v1/receipts/{execution_id}")
def receipt(execution_id: str, _authorized: None = Depends(require_verifier)) -> dict:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM receipts WHERE execution_id=?", (execution_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="receipt not found")
    return json.loads(row["receipt_json"])


@app.get("/v1/executions/{execution_id}")
def execution(execution_id: str, _authorized: None = Depends(require_verifier)) -> dict:
    with connect() as database:
        row = database.execute("SELECT record_json FROM executions WHERE execution_id=?", (execution_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="execution not found")
    return json.loads(row["record_json"])
