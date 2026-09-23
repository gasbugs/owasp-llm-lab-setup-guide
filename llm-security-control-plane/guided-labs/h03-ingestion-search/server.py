"""Learner-owned H03 ingestion and retrieval coordinator."""

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
SERVICE_TOKEN = os.environ["GUIDED_H03_GATEWAY_TOKEN"]
CONTROL_TOKEN = os.environ["GUIDED_CONTROL_LAB03_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_LAB03_TOKEN"]
DATABASE_PATH = os.getenv("GUIDED_H03_DATABASE", "/tmp/h03-receipts.sqlite3")

Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        "CREATE TABLE IF NOT EXISTS jobs "
        "(execution_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, started_at TEXT NOT NULL)"
    )
    database.execute(
        "CREATE TABLE IF NOT EXISTS receipts "
        "(execution_id TEXT NOT NULL, phase TEXT NOT NULL, receipt_json TEXT NOT NULL, "
        "PRIMARY KEY(execution_id, phase))"
    )


class SyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str


class SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    phase: Literal["early", "final"]


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


def save_receipt(execution_id: str, phase: str, receipt: dict) -> None:
    with connect() as database:
        database.execute(
            "INSERT OR REPLACE INTO receipts VALUES(?,?,?)",
            (execution_id, phase, json.dumps(receipt, ensure_ascii=False)),
        )


def current_job(execution_id: str) -> sqlite3.Row:
    with connect() as database:
        row = database.execute(
            "SELECT execution_id,job_id,started_at FROM jobs WHERE execution_id=?",
            (execution_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="current ingestion job is missing")
    return row


def may_retrieve(current_job_id: str, observed_job_id: str, status: str) -> bool:
    """Starter: retrieval is allowed before the current job is complete."""
    # TODO(H03): 같은 현재 job이고 상태가 COMPLETE일 때만 True를 반환한다.
    return True


def start_sync(request: SyncRequest) -> dict:
    response = httpx.post(
        f"{GATEWAY_URL}/v1/h03/ingestions",
        json={"execution_id": request.execution_id},
        headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
        timeout=30.0,
    )
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="H03 ingestion did not start")
    provider = response.json()
    with connect() as database:
        database.execute(
            "INSERT INTO jobs VALUES(?,?,?)",
            (request.execution_id, provider["ingestion_job_id"], request.started_at),
        )
    receipt = {
        "execution_id": request.execution_id,
        "phase": "start",
        "started_at": request.started_at,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "source_digest": source_digest(),
        "ingestion_job_id": provider["ingestion_job_id"],
        "job_status": provider["status"],
        "upstream_called": True,
    }
    save_receipt(request.execution_id, "start", receipt)
    return receipt


def job_status(execution_id: str) -> dict:
    job = current_job(execution_id)
    response = httpx.get(
        f"{GATEWAY_URL}/v1/h03/ingestions/{job['job_id']}",
        headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
        timeout=10.0,
    )
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="H03 ingestion status is unavailable")
    return response.json()


def search_current(request: SearchRequest) -> dict:
    job = current_job(request.execution_id)
    status_receipt = job_status(request.execution_id)
    allowed = may_retrieve(
        job["job_id"], status_receipt["ingestion_job_id"], status_receipt["status"]
    )
    base = {
        "execution_id": request.execution_id,
        "phase": request.phase,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "source_digest": source_digest(),
        "ingestion_job_id": job["job_id"],
        "observed_job_id": status_receipt["ingestion_job_id"],
        "job_status": status_receipt["status"],
    }
    if not allowed:
        receipt = {**base, "decision": "wait", "retrieval_called": False}
        save_receipt(request.execution_id, request.phase, receipt)
        raise HTTPException(status_code=409, detail=receipt)

    response = httpx.post(
        f"{GATEWAY_URL}/v1/h03/retrievals",
        json={
            "execution_id": request.execution_id,
            "phase": request.phase,
            "ingestion_job_id": job["job_id"],
        },
        headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
        timeout=30.0,
    )
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="H03 retrieval failed")
    provider = response.json()
    receipt = {
        **base,
        "decision": "retrieve",
        "retrieval_called": True,
        "retrieval_request_id": provider["provider_request_id"],
        "source_uris": provider["source_uris"],
        "document_ids": provider["document_ids"],
    }
    save_receipt(request.execution_id, request.phase, receipt)
    return {**receipt, "result": provider}


app = FastAPI(title="Tenant 03 H03 Sync App", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    with connect() as database:
        database.execute("SELECT 1").fetchone()
    return {"status": "ready", "provider_check": "not-run"}


@app.post("/v1/sync")
def sync(request: SyncRequest, _authorized: None = Depends(require_control)) -> dict:
    try:
        return start_sync(request)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="Bedrock Gateway unavailable") from exc


@app.get("/v1/status/{execution_id}")
def status(execution_id: str, _authorized: None = Depends(require_control)) -> dict:
    try:
        return job_status(execution_id)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="Bedrock Gateway unavailable") from exc


@app.post("/v1/search")
def search(request: SearchRequest, _authorized: None = Depends(require_control)) -> dict:
    try:
        return search_current(request)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="Bedrock Gateway unavailable") from exc


@app.get("/v1/build-info")
def build_info(_authorized: None = Depends(require_verifier)) -> dict[str, str]:
    return {"component": "guided-h03-sync-app", "source_digest": source_digest()}


@app.get("/v1/receipts/{execution_id}/{phase}")
def receipt(
    execution_id: str,
    phase: Literal["start", "early", "final"],
    _authorized: None = Depends(require_verifier),
) -> dict:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM receipts WHERE execution_id=? AND phase=?",
            (execution_id, phase),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="receipt not found")
    return json.loads(row["receipt_json"])
