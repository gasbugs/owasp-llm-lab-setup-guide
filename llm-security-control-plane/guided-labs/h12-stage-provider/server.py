"""Independent H12 protected-stage ledger and deterministic failure provider."""

from __future__ import annotations

import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field


SERVICE_TOKEN = os.environ["GUIDED_H12_SERVICE_TOKEN"]
CONTROL_TOKEN = os.environ["GUIDED_H12_PROVIDER_CONTROL_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_H12_PROVIDER_VERIFIER_TOKEN"]
DATABASE_PATH = Path(os.getenv("GUIDED_H12_PROVIDER_DATABASE", "/state/ledger.sqlite3"))
STAGES = ("authenticate", "authorize", "input_privacy", "input_rail", "retrieval", "main", "output_rail", "output_privacy")
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute("CREATE TABLE IF NOT EXISTS suites (suite_id TEXT PRIMARY KEY, started_at TEXT NOT NULL)")
    database.execute("CREATE TABLE IF NOT EXISTS calls (id INTEGER PRIMARY KEY AUTOINCREMENT, suite_id TEXT NOT NULL, case_id TEXT NOT NULL, stage TEXT NOT NULL, status INTEGER NOT NULL, authorized INTEGER NOT NULL, observed_at TEXT NOT NULL)")


class SuiteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str


class StageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    case_id: str = Field(pattern=r"^(normal|invalid-token|indirect-injection|nemo-timeout)$")


def token_ok(expected: str, authorization: str | None) -> bool:
    scheme, _, token = (authorization or "").partition(" ")
    return scheme.lower() == "bearer" and hmac.compare_digest(token, expected)


def require(expected: str, authorization: str | None) -> None:
    if not token_ok(expected, authorization):
        raise HTTPException(status_code=401, detail="invalid service credential")


def record(suite_id: str, case_id: str, stage: str, status: int, authorized: bool) -> None:
    with connect() as database:
        database.execute("INSERT INTO calls (suite_id,case_id,stage,status,authorized,observed_at) VALUES(?,?,?,?,?,?)", (suite_id, case_id, stage, status, int(authorized), datetime.now(timezone.utc).isoformat()))


app = FastAPI(title="Tenant 03 H12 Protected Stages", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    return {"status": "ready"}


@app.post("/v1/suites")
def create_suite(request: SuiteRequest, authorization: str | None = Header(default=None)) -> dict:
    require(CONTROL_TOKEN, authorization)
    try:
        with connect() as database:
            database.execute("INSERT INTO suites VALUES(?,?)", (request.suite_id, request.started_at))
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="suite exists") from exc
    return {"suite_id": request.suite_id}


@app.post("/v1/stages/{stage}")
def execute_stage(stage: str, request: StageRequest, authorization: str | None = Header(default=None)) -> dict:
    if stage not in STAGES:
        raise HTTPException(status_code=404, detail="unknown stage")
    require(SERVICE_TOKEN, authorization)
    status = 200
    if stage == "authenticate" and request.case_id == "invalid-token":
        status = 401
    elif stage == "input_rail" and request.case_id == "indirect-injection":
        status = 403
    elif stage == "input_rail" and request.case_id == "nemo-timeout":
        status = 503
    record(request.suite_id, request.case_id, stage, status, True)
    if status != 200:
        raise HTTPException(status_code=status, detail=f"{stage} stopped")
    return {"stage": stage, "status": status}


@app.post("/v1/protected/{suite_id}")
def direct_access(suite_id: str, authorization: str | None = Header(default=None)) -> dict:
    authorized = token_ok(SERVICE_TOKEN, authorization)
    record(suite_id, "direct-protected", "protected_direct", 200 if authorized else 401, authorized)
    if not authorized:
        raise HTTPException(status_code=401, detail="service credential required")
    return {"side_effect": "unexpected"}


@app.get("/v1/suites/{suite_id}/ledger")
def ledger(suite_id: str, authorization: str | None = Header(default=None)) -> dict:
    require(VERIFIER_TOKEN, authorization)
    with connect() as database:
        suite = database.execute("SELECT * FROM suites WHERE suite_id=?", (suite_id,)).fetchone()
        calls = database.execute("SELECT case_id,stage,status,authorized,observed_at FROM calls WHERE suite_id=? ORDER BY id", (suite_id,)).fetchall()
    if suite is None:
        raise HTTPException(status_code=404, detail="suite not found")
    return {"suite_id": suite_id, "started_at": suite["started_at"], "calls": [dict(item) for item in calls]}
