"""Read-only verifier that distrusts Browser and executor verdict fields."""

from __future__ import annotations

import hmac
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field


LAB_URL = os.getenv("GUIDED_LAB01_URL", "http://guided-lab-01-nova:8000")
GATEWAY_URL = os.getenv("GUIDED_BEDROCK_GATEWAY_URL", "http://guided-bedrock-gateway:8080")
CONTROL_TOKEN = os.environ["GUIDED_CONTROL_VERIFIER_TOKEN"]
LAB_TOKEN = os.environ["GUIDED_VERIFIER_LAB01_TOKEN"]
GATEWAY_TOKEN = os.environ["GUIDED_VERIFIER_GATEWAY_TOKEN"]
DATABASE_PATH = os.getenv("GUIDED_VERIFIER_DATABASE", "/state/verifier.sqlite3")
MODEL_ID = "us.amazon.nova-lite-v1:0"

Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        """CREATE TABLE IF NOT EXISTS used_evidence (
        provider_request_id TEXT PRIMARY KEY,
        execution_id TEXT NOT NULL UNIQUE
        )"""
    )


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    expected_config_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_max_output_tokens: int = Field(ge=1, le=512)
    run_kind: Literal["observe", "bounded", "preflight"]


def require_control(authorization: str | None = Header(default=None)) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, CONTROL_TOKEN):
        raise HTTPException(status_code=401, detail="invalid service credential")


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone is required")
    return parsed.astimezone(timezone.utc)


def err_envelope(request: VerifyRequest, reason: str) -> dict:
    return {
        "lab_id": "01-nova",
        "exercise_id": "01",
        "execution_id": request.execution_id,
        "execution_kind": "live-provider",
        "started_at": request.started_at,
        "status": "completed",
        "course_verdict": "ERR",
        "verified_by": "guided-evidence-verifier",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "stage_calls": [],
        "evidence": [],
        "reason": reason,
        "next_check": "Gateway와 실행기 영수증의 실행 ID·시각·설정 digest를 확인합니다.",
    }


app = FastAPI(title="Tenant 03 Evidence Verifier", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    with connect() as database:
        database.execute("SELECT 1").fetchone()
    return {"status": "ready", "identity": "read-only-verifier"}


@app.post("/v1/verify/lab-01")
def verify(
    request: VerifyRequest, _authorized: None = Depends(require_control)
) -> dict:
    try:
        lab_response = httpx.get(
            f"{LAB_URL}/v1/receipts/{request.execution_id}",
            headers={"Authorization": f"Bearer {LAB_TOKEN}"},
            timeout=5.0,
        )
        gateway_response = httpx.get(
            f"{GATEWAY_URL}/v1/evidence/{request.execution_id}",
            headers={"Authorization": f"Bearer {GATEWAY_TOKEN}"},
            timeout=5.0,
        )
    except httpx.RequestError:
        return err_envelope(request, "read-only evidence endpoint unavailable")
    if lab_response.status_code != 200 or gateway_response.status_code != 200:
        return err_envelope(request, "executor or provider evidence is missing")

    lab = lab_response.json()
    provider = gateway_response.json()
    try:
        started_at = parse_time(request.started_at)
        observed_at = parse_time(provider["observed_at"])
    except (KeyError, TypeError, ValueError):
        return err_envelope(request, "evidence timestamp is invalid")

    evidence_matches = all(
        (
            lab.get("execution_id") == request.execution_id,
            provider.get("execution_id") == request.execution_id,
            lab.get("provider_request_id") == provider.get("provider_request_id"),
            lab.get("config_digest") == request.expected_config_digest,
            provider.get("config_digest") == request.expected_config_digest,
            provider.get("model_id") == MODEL_ID,
            provider.get("forwarded_parameters", {}).get("maxTokens")
            == request.expected_max_output_tokens,
            observed_at >= started_at,
        )
    )
    usage = provider.get("usage", {})
    usage_valid = (
        type(usage.get("outputTokens")) is int
        and 0 <= usage["outputTokens"] <= request.expected_max_output_tokens
    )
    provider_id = provider.get("provider_request_id")
    if not evidence_matches or not usage_valid or not isinstance(provider_id, str) or not provider_id:
        return err_envelope(request, "provider fields do not match the requested execution")

    try:
        with connect() as database:
            database.execute(
                "INSERT INTO used_evidence VALUES(?,?)",
                (provider_id, request.execution_id),
            )
    except sqlite3.IntegrityError:
        with connect() as database:
            row = database.execute(
                "SELECT execution_id FROM used_evidence WHERE provider_request_id=?",
                (provider_id,),
            ).fetchone()
        if row is None or row["execution_id"] != request.execution_id:
            return err_envelope(request, "stale provider evidence was reused")

    verdict = "PASS"
    reason = "Provider에 전달한 출력 상한과 실제 사용량이 일치합니다."
    if request.run_kind == "bounded" and request.expected_max_output_tokens > 128:
        if usage["outputTokens"] > 128:
            verdict = "HIT"
            reason = "운영 상한 128보다 큰 출력 사용량이 실제로 확인됐습니다."
        else:
            verdict = "ERR"
            reason = "상한은 너무 크지만 이번 응답이 짧아 실제 자원 영향을 확정할 수 없습니다."

    return {
        "lab_id": "01-nova",
        "exercise_id": "01",
        "execution_id": request.execution_id,
        "execution_kind": "live-provider",
        "started_at": request.started_at,
        "status": "completed",
        "course_verdict": verdict,
        "verified_by": "guided-evidence-verifier",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "stage_calls": [
            {
                "stage": "gateway_output_limit",
                "attempted": True,
                "outcome": "allow",
                "evidence_id": request.expected_config_digest,
            },
            {
                "stage": "bedrock_main",
                "attempted": True,
                "outcome": "completed",
                "evidence_id": provider_id,
            },
        ],
        "evidence": [
            {
                "source": "amazon-bedrock"
                if provider.get("provider_mode") == "aws"
                else "contract-provider",
                "kind": "request",
                "id": provider_id,
                "observed_at": provider["observed_at"],
            }
        ],
        "result": {
            "model_id": provider["model_id"],
            "region": provider["region"],
            "forwarded_parameters": provider["forwarded_parameters"],
            "usage": usage,
            "stop_reason": provider["stop_reason"],
            "output_text": provider["output_text"],
            "provider_mode": provider["provider_mode"],
        },
        "reason": reason,
        "next_check": "forwarded_parameters.maxTokens와 usage.outputTokens를 비교합니다.",
    }
