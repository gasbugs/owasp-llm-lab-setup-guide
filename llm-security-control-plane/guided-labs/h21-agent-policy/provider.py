"""Deterministic H21 model-provider fixture with verifier-owned audit access."""

from __future__ import annotations

import hmac
import os
import threading
import uuid

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field


HOST_TOKEN = os.environ["GUIDED_H21_PROVIDER_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_H21_TOKEN"]
CALLS: list[dict] = []
LOCK = threading.Lock()


def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_host(authorization: str | None = Header(default=None)) -> None:
    bearer(HOST_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


class ProviderCall(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    case_id: str = Field(min_length=1, max_length=64)
    trace_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    principal: str
    model: str
    stage: str = Field(pattern="^(proposal|final)$")


app = FastAPI(title="H21 deterministic provider", docs_url=None, redoc_url=None)


@app.get("/readyz")
def readyz() -> dict:
    return {"status": "ready", "provider": "deterministic-training-fixture"}


@app.post("/v1/generate")
def generate(call: ProviderCall, _authorized: None = Depends(require_host)) -> dict:
    record = {**call.model_dump(), "provider_request_id": str(uuid.uuid4())}
    with LOCK:
        CALLS.append(record)
    return {
        **record,
        "usage": {"input_tokens": 8, "output_tokens": 4},
        "text": "lookup_notice" if call.stage == "proposal" else "처리 완료",
    }


@app.get("/v1/audit/{suite_id}")
def audit(suite_id: str, _authorized: None = Depends(require_verifier)) -> dict:
    with LOCK:
        calls = [item for item in CALLS if item["suite_id"] == suite_id]
    return {"suite_id": suite_id, "calls": calls}
