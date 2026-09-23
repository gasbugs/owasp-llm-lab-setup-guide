"""Read-only verifier for H01 learner Gateway receipts."""

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


LAB_URL = os.getenv("GUIDED_LAB01_URL", "http://guided-h01-gateway:8000")
CONTROL_TOKEN = os.environ["GUIDED_CONTROL_VERIFIER_TOKEN"]
LAB_TOKEN = os.environ["GUIDED_VERIFIER_LAB01_TOKEN"]
DATABASE_PATH = os.getenv("GUIDED_VERIFIER_DATABASE", "/state/verifier.sqlite3")
MODEL_ID = "us.amazon.nova-lite-v1:0"

Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        "CREATE TABLE IF NOT EXISTS used_evidence "
        "(provider_request_id TEXT PRIMARY KEY, execution_id TEXT NOT NULL UNIQUE)"
    )


class ExpectedCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: Literal[
        "provider-preflight",
        "normal-64",
        "risk-512",
        "invalid-empty-message",
        "reject-model-override",
    ]
    scenario: Literal["preflight", "normal", "risk"]
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    requested_max_output_tokens: int = Field(ge=1, le=512)
    expected_status: Literal[200, 422]
    observed_status: int


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    suite_kind: Literal["preflight", "hands_on"]
    cases: list[ExpectedCase] = Field(min_length=1, max_length=4)


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
        "activity_id": "H01",
        "execution_id": request.suite_id,
        "execution_kind": "learner-gateway-suite",
        "started_at": request.started_at,
        "status": "completed",
        "course_verdict": "ERR",
        "verified_by": "guided-evidence-verifier",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "stage_calls": [],
        "evidence": [],
        "reason": reason,
        "next_check": "Gateway 요청 schema, source digest와 Provider request ID를 확인합니다.",
    }


def reserve_provider_evidence(provider_id: str, execution_id: str) -> bool:
    try:
        with connect() as database:
            database.execute(
                "INSERT INTO used_evidence VALUES(?,?)", (provider_id, execution_id)
            )
        return True
    except sqlite3.IntegrityError:
        with connect() as database:
            row = database.execute(
                "SELECT execution_id FROM used_evidence WHERE provider_request_id=?",
                (provider_id,),
            ).fetchone()
        return row is not None and row["execution_id"] == execution_id


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
def verify(request: VerifyRequest, _authorized: None = Depends(require_control)) -> dict:
    expected_ids = (
        {"provider-preflight"}
        if request.suite_kind == "preflight"
        else {"normal-64", "risk-512", "invalid-empty-message", "reject-model-override"}
    )
    if {item.case_id for item in request.cases} != expected_ids:
        return err_envelope(request, "the server-owned test suite is incomplete")

    try:
        build_response = httpx.get(
            f"{LAB_URL}/v1/build-info",
            headers={"Authorization": f"Bearer {LAB_TOKEN}"},
            timeout=5.0,
        )
        if build_response.status_code != 200:
            return err_envelope(request, "learner Gateway build information is missing")
        source_digest = build_response.json().get("source_digest")
        if not isinstance(source_digest, str) or len(source_digest) != 64:
            return err_envelope(request, "learner Gateway source digest is invalid")

        verified_cases = []
        evidence = []
        for expected in request.cases:
            if expected.observed_status != expected.expected_status:
                return err_envelope(request, f"{expected.case_id} returned an unexpected HTTP status")
            receipt_response = httpx.get(
                f"{LAB_URL}/v1/receipts/{expected.execution_id}",
                headers={"Authorization": f"Bearer {LAB_TOKEN}"},
                timeout=5.0,
            )
            if expected.expected_status == 422:
                if receipt_response.status_code != 404:
                    return err_envelope(request, f"{expected.case_id} reached the Provider path")
                verified_cases.append(
                    {
                        "case_id": expected.case_id,
                        "execution_id": expected.execution_id,
                        "http_status": 422,
                        "upstream_called": False,
                    }
                )
                continue
            if receipt_response.status_code != 200:
                return err_envelope(request, "learner Gateway receipt is missing")

            receipt = receipt_response.json()
            effective = receipt.get("effective_max_output_tokens")
            usage = receipt.get("usage", {})
            provider_id = receipt.get("provider_request_id")
            try:
                started_at = parse_time(expected.started_at)
                observed_at = parse_time(receipt["observed_at"])
            except (KeyError, TypeError, ValueError):
                return err_envelope(request, "evidence timestamp is invalid")
            fields_match = all(
                (
                    receipt.get("execution_id") == expected.execution_id,
                    receipt.get("scenario") == expected.scenario,
                    receipt.get("requested_max_output_tokens") == expected.requested_max_output_tokens,
                    receipt.get("source_digest") == source_digest,
                    receipt.get("model_id") == MODEL_ID,
                    receipt.get("region") == "us-east-1",
                    receipt.get("forwarded_parameters", {}).get("maxTokens") == effective,
                    receipt.get("upstream_called") is True,
                    type(effective) is int,
                    type(usage.get("outputTokens")) is int,
                    0 <= usage.get("outputTokens", -1) <= effective,
                    isinstance(provider_id, str),
                    bool(provider_id),
                    observed_at >= started_at,
                )
            )
            if not fields_match:
                return err_envelope(request, "Gateway receipt does not match the requested execution")
            if not reserve_provider_evidence(provider_id, expected.execution_id):
                return err_envelope(request, "stale Provider evidence was reused")
            item = {
                "case_id": expected.case_id,
                "execution_id": expected.execution_id,
                "http_status": 200,
                "requested_max_output_tokens": expected.requested_max_output_tokens,
                "effective_max_output_tokens": effective,
                "source_digest": source_digest,
                "provider_request_id": provider_id,
                "model_id": receipt["model_id"],
                "region": receipt["region"],
                "forwarded_parameters": receipt["forwarded_parameters"],
                "usage": usage,
                "stop_reason": receipt["stop_reason"],
                "output_text": receipt["response_text"],
                "provider_mode": receipt["provider_mode"],
                "upstream_called": True,
            }
            verified_cases.append(item)
            evidence.append(
                {
                    "source": "amazon-bedrock" if receipt["provider_mode"] == "aws" else "contract-provider",
                    "kind": expected.case_id,
                    "id": provider_id,
                    "observed_at": receipt["observed_at"],
                }
            )
    except httpx.RequestError:
        return err_envelope(request, "read-only Gateway evidence endpoint unavailable")

    by_id = {item["case_id"]: item for item in verified_cases}
    verdict = "PASS"
    reason = "Gateway와 Provider의 새 영수증을 확인했습니다."
    if request.suite_kind == "hands_on":
        normal = by_id["normal-64"]
        risk = by_id["risk-512"]
        if normal["effective_max_output_tokens"] != 64:
            verdict = "ERR"
            reason = "정상 64 Token 요청까지 바꾸어 정상 기능 유지를 확인할 수 없습니다."
        elif risk["effective_max_output_tokens"] <= 128:
            reason = "정상 요청은 유지하고 큰 요청은 제한했으며 잘못된 body와 모델 변경도 Provider 전에 거부했습니다."
        elif risk["usage"]["outputTokens"] > 128:
            verdict = "HIT"
            reason = "512 Token 요청이 제한 없이 실제 Provider 출력으로 이어졌습니다."
        else:
            verdict = "ERR"
            reason = "전달 상한은 크지만 이번 응답이 짧아 실제 영향을 확정할 수 없습니다."

    focus = next(item for item in reversed(verified_cases) if item.get("http_status") == 200)
    return {
        "lab_id": "01-nova",
        "activity_id": "H01",
        "execution_id": request.suite_id,
        "execution_kind": "learner-gateway-suite",
        "started_at": request.started_at,
        "status": "completed",
        "course_verdict": verdict,
        "verified_by": "guided-evidence-verifier",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "stage_calls": [
            {"stage": "learner_gateway", "attempted": True, "outcome": "completed", "evidence_id": source_digest},
            {"stage": "bedrock_main", "attempted": True, "outcome": "completed", "evidence_id": focus["provider_request_id"]},
        ],
        "evidence": evidence,
        "result": {**focus, "cases": verified_cases},
        "reason": reason,
        "next_check": "네 case의 HTTP 상태, upstream_called와 Provider maxTokens를 순서대로 비교합니다.",
    }
