"""Loopback-only HTTP API for the Presidio privacy spoke."""

from __future__ import annotations

import hmac
import json
import os

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from policy import PrivacyAnalyzer
from telemetry import configure_telemetry


INTERNAL_TOKEN = os.environ["PRESIDIO_INTERNAL_TOKEN"]
RELEASE_VERSION = os.getenv("RELEASE_VERSION", "1.0.0")
if not INTERNAL_TOKEN:
    raise RuntimeError("PRESIDIO_INTERNAL_TOKEN is required")

ANALYZER = PrivacyAnalyzer()
app = FastAPI(title="Presidio privacy spoke", docs_url=None, redoc_url=None)
configure_telemetry(app, "llm-security-presidio-spoke")


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stage: str = Field(pattern="^(input|retrieval|output)$")
    text: str = Field(min_length=1, max_length=50000)
    request_id: str = Field(min_length=8, max_length=128)


def require_internal_token(authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, INTERNAL_TOKEN):
        raise HTTPException(status_code=401, detail="internal service token required")


def emit_metadata(result: dict) -> None:
    event = {
        "event": "privacy_spoke_scan",
        "request_id": result["request_id"],
        "spoke": result["spoke"],
        "stage": result["stage"],
        "valid": result["valid"],
        "risk_score": result["risk_score"],
        "entity_types": result["entity_types"],
        "detection_count": len(result["detections"]),
        "duration_ms": result["duration_ms"],
    }
    print(json.dumps(event, separators=(",", ":")), flush=True)


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "service": "presidio-privacy-spoke", "version": RELEASE_VERSION}


@app.get("/api/policy")
async def policy() -> dict:
    return {
        "service": "presidio-privacy-spoke",
        "version": RELEASE_VERSION,
        "canonical_source": "llm-security-control-plane/spokes/presidio-privacy/policy.py",
        **ANALYZER.public_policy(),
    }


@app.post("/api/analyze")
async def analyze(
    request: AnalyzeRequest,
    authorization: str | None = Header(default=None),
) -> dict:
    require_internal_token(authorization)
    result = ANALYZER.analyze(
        stage=request.stage,
        text=request.text,
        request_id=request.request_id,
    )
    emit_metadata(result)
    return result
