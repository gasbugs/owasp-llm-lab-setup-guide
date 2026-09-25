"""Read-only historical H04 snapshots; execution moved to P04."""

from __future__ import annotations

import hmac
import json
import os
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException


AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
DATABASE_PATH = os.getenv("GUIDED_GATEWAY_DATABASE", "/state/evidence.sqlite3")
RUNTIME_TOKEN = os.environ["GUIDED_H04_GATEWAY_TOKEN"]
PROVISION_TOKEN = os.environ["GUIDED_LAB04_PROVISION_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_GATEWAY_TOKEN"]


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        "CREATE TABLE IF NOT EXISTS h04_evidence "
        "(execution_id TEXT PRIMARY KEY, provider_request_id TEXT NOT NULL UNIQUE, "
        "receipt_json TEXT NOT NULL)"
    )




def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_runtime(authorization: str | None = Header(default=None)) -> None:
    bearer(RUNTIME_TOKEN, authorization)


def require_provision(authorization: str | None = Header(default=None)) -> None:
    bearer(PROVISION_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


def load_state() -> dict[str, Any] | None:
    with connect() as database:
        row = database.execute(
            "SELECT state_json FROM resource_state WHERE logical_name='h04'"
        ).fetchone()
    return json.loads(row["state_json"]) if row else None




router = APIRouter()


@router.post("/v1/h04/provision")
def provision_route(
    _authorized: None = Depends(require_provision)
) -> dict[str, Any]:
    raise HTTPException(status_code=410, detail="H04 provisioning retired; use /v1/p04/resources/prepare")


@router.get("/v1/h04/resources")
def resources(_authorized: None = Depends(require_verifier)) -> dict[str, Any]:
    return load_state() or {"status": "MISSING", "region": AWS_REGION}


@router.post("/v1/h04/apply")
@router.post("/v1/h04/converse")
def retired_execution(_authorized: None = Depends(require_runtime)) -> dict[str, Any]:
    raise HTTPException(status_code=410, detail="H04 execution retired; use the P04 runner")


@router.get("/v1/h04/evidence/{execution_id}")
def evidence(
    execution_id: str, _authorized: None = Depends(require_verifier)
) -> dict[str, Any]:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM h04_evidence WHERE execution_id=?", (execution_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="H04 evidence not found")
    return json.loads(row["receipt_json"])
