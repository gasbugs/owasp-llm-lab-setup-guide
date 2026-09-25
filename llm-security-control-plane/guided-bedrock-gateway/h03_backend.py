"""Retired H03 endpoints and read-only historical snapshots; P03 is separate."""

from __future__ import annotations

import hmac
import json
import os
import sqlite3
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException


AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
DATABASE_PATH = os.getenv("GUIDED_GATEWAY_DATABASE", "/state/evidence.sqlite3")
RUNTIME_TOKEN = os.environ["GUIDED_H03_GATEWAY_TOKEN"]
PROVISION_TOKEN = os.environ["GUIDED_LAB03_PROVISION_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_GATEWAY_TOKEN"]


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        "CREATE TABLE IF NOT EXISTS h03_retrieval_evidence "
        "(execution_id TEXT NOT NULL, phase TEXT NOT NULL, provider_request_id TEXT NOT NULL UNIQUE, "
        "receipt_json TEXT NOT NULL, PRIMARY KEY(execution_id, phase))"
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
            "SELECT state_json FROM resource_state WHERE logical_name='h03'"
        ).fetchone()
    return json.loads(row["state_json"]) if row else None


router = APIRouter()


@router.post("/v1/h03/provision")
def provision(_authorized: None = Depends(require_provision)) -> dict:
    raise HTTPException(status_code=410, detail="H03 execution retired; use P03 resource preparation.")


@router.post("/v1/h03/ingestions")
def start_ingestion(_authorized: None = Depends(require_runtime)) -> dict:
    raise HTTPException(status_code=410, detail="H03 execution retired; use the P03 suite.")


@router.get("/v1/h03/ingestions/{job_id}")
def ingestion(job_id: str, _authorized: None = Depends(require_runtime)) -> dict:
    raise HTTPException(status_code=410, detail="H03 execution retired; use the P03 suite.")


@router.post("/v1/h03/retrievals")
def retrieval(_authorized: None = Depends(require_runtime)) -> dict:
    raise HTTPException(status_code=410, detail="H03 execution retired; use the P03 suite.")


@router.get("/v1/h03/resources")
def resources(_authorized: None = Depends(require_verifier)) -> dict:
    state = load_state()
    return state if state is not None else {"status": "MISSING", "region": AWS_REGION}


@router.get("/v1/h03/jobs/{job_id}")
def job_evidence(job_id: str, _authorized: None = Depends(require_verifier)) -> dict:
    job = (load_state() or {}).get("current_job")
    if not isinstance(job, dict) or job.get("ingestion_job_id") != job_id:
        raise HTTPException(status_code=404, detail="H03 historical job not found")
    return dict(job)


@router.get("/v1/h03/retrievals/{execution_id}/{phase}")
def retrieval_evidence(
    execution_id: str,
    phase: Literal["early", "final"],
    _authorized: None = Depends(require_verifier),
) -> dict:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM h03_retrieval_evidence WHERE execution_id=? AND phase=?",
            (execution_id, phase),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="H03 retrieval evidence not found")
    return json.loads(row["receipt_json"])
