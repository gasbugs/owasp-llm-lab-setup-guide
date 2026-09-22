"""Read-only verifier for the learner application and Provider receipts."""

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


LAB_URL = os.getenv("GUIDED_LAB01_URL", "http://guided-student-app:8000")
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


class ExpectedCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: Literal["provider-preflight", "normal-64", "risk-512"]
    scenario: Literal["preflight", "normal", "risk"]
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    requested_max_output_tokens: int = Field(ge=1, le=512)


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    suite_kind: Literal["preflight", "hands_on"]
    cases: list[ExpectedCase] = Field(min_length=1, max_length=2)


def require_control(authorization: str | None = Header(default=None)) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, CONTROL_TOKEN):
        raise HTTPException(status_code=401, detail="invalid service credential")


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone is required")
    return parsed.astimezone(timezone.utc)


def config_digest(max_output_tokens: int) -> str:
    encoded = json.dumps(
        {
            "model_id": MODEL_ID,
            "inference_config": {"maxTokens": max_output_tokens, "temperature": 0.0},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def err_envelope(request: VerifyRequest, reason: str) -> dict:
    return {
        "lab_id": "01-nova",
        "activity_id": "H01",
        "execution_id": request.suite_id,
        "execution_kind": "learner-application-suite",
        "started_at": request.started_at,
        "status": "completed",
        "course_verdict": "ERR",
        "verified_by": "guided-evidence-verifier",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "stage_calls": [],
        "evidence": [],
        "reason": reason,
        "next_check": "student app과 Gateway receipt의 실행 ID·시각·적용 상한을 확인합니다.",
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
        else {"normal-64", "risk-512"}
    )
    if {item.case_id for item in request.cases} != expected_ids:
        return err_envelope(request, "the server-owned test suite is incomplete")

    verified_cases = []
    evidence = []
    try:
        for expected in request.cases:
            lab_response = httpx.get(
                f"{LAB_URL}/v1/receipts/{expected.execution_id}",
                headers={"Authorization": f"Bearer {LAB_TOKEN}"},
                timeout=5.0,
            )
            gateway_response = httpx.get(
                f"{GATEWAY_URL}/v1/evidence/{expected.execution_id}",
                headers={"Authorization": f"Bearer {GATEWAY_TOKEN}"},
                timeout=5.0,
            )
            if lab_response.status_code != 200 or gateway_response.status_code != 200:
                return err_envelope(request, "student app or provider evidence is missing")
            lab = lab_response.json()
            provider = gateway_response.json()
            effective = lab.get("effective_max_output_tokens")
            provider_id = provider.get("provider_request_id")
            try:
                started_at = parse_time(expected.started_at)
                observed_at = parse_time(provider["observed_at"])
            except (KeyError, TypeError, ValueError):
                return err_envelope(request, "evidence timestamp is invalid")
            if type(effective) is not int or not 1 <= effective <= 512:
                return err_envelope(request, "student app returned an invalid effective limit")
            digest = config_digest(effective)
            usage = provider.get("usage", {})
            fields_match = all(
                (
                    lab.get("execution_id") == expected.execution_id,
                    lab.get("scenario") == expected.scenario,
                    lab.get("requested_max_output_tokens") == expected.requested_max_output_tokens,
                    provider.get("execution_id") == expected.execution_id,
                    lab.get("provider_request_id") == provider_id,
                    lab.get("config_digest") == digest,
                    provider.get("config_digest") == digest,
                    provider.get("model_id") == MODEL_ID,
                    provider.get("forwarded_parameters", {}).get("maxTokens") == effective,
                    type(usage.get("outputTokens")) is int,
                    0 <= usage.get("outputTokens", -1) <= effective,
                    isinstance(lab.get("policy_digest"), str),
                    len(lab.get("policy_digest", "")) == 64,
                    isinstance(provider_id, str),
                    bool(provider_id),
                    observed_at >= started_at,
                )
            )
            if not fields_match:
                return err_envelope(request, "receipts do not match the requested execution")
            if not reserve_provider_evidence(provider_id, expected.execution_id):
                return err_envelope(request, "stale provider evidence was reused")
            item = {
                "case_id": expected.case_id,
                "execution_id": expected.execution_id,
                "requested_max_output_tokens": expected.requested_max_output_tokens,
                "effective_max_output_tokens": effective,
                "policy_digest": lab["policy_digest"],
                "provider_request_id": provider_id,
                "model_id": provider["model_id"],
                "region": provider["region"],
                "forwarded_parameters": provider["forwarded_parameters"],
                "usage": usage,
                "stop_reason": provider["stop_reason"],
                "output_text": provider["output_text"],
                "provider_mode": provider["provider_mode"],
            }
            verified_cases.append(item)
            evidence.append(
                {
                    "source": "amazon-bedrock"
                    if provider.get("provider_mode") == "aws"
                    else "contract-provider",
                    "kind": expected.case_id,
                    "id": provider_id,
                    "observed_at": provider["observed_at"],
                }
            )
    except httpx.RequestError:
        return err_envelope(request, "read-only evidence endpoint unavailable")

    by_id = {item["case_id"]: item for item in verified_cases}
    verdict = "PASS"
    reason = "Provider 연결과 새 receipt를 확인했습니다."
    if request.suite_kind == "hands_on":
        normal = by_id["normal-64"]
        risk = by_id["risk-512"]
        if normal["effective_max_output_tokens"] != 64:
            verdict = "ERR"
            reason = "정상 64 Token 요청까지 바꾸어 정상 기능 유지를 확인할 수 없습니다."
        elif risk["effective_max_output_tokens"] <= 128:
            verdict = "PASS"
            reason = "정상 요청은 유지하고 위험 요청의 실제 Provider 상한을 128 이하로 제한했습니다."
        elif risk["usage"]["outputTokens"] > 128:
            verdict = "HIT"
            reason = "위험 요청이 운영 상한 128을 넘어 실제 Provider 출력을 사용했습니다."
        else:
            verdict = "ERR"
            reason = "전달 상한은 커지만 이번 응답이 짧어 실제 영향을 확정할 수 없습니다."

    focus = verified_cases[-1]
    return {
        "lab_id": "01-nova",
        "activity_id": "H01",
        "execution_id": request.suite_id,
        "execution_kind": "learner-application-suite",
        "started_at": request.started_at,
        "status": "completed",
        "course_verdict": verdict,
        "verified_by": "guided-evidence-verifier",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "stage_calls": [
            {"stage": "student_output_policy", "attempted": True, "outcome": "completed", "evidence_id": focus["policy_digest"]},
            {"stage": "bedrock_main", "attempted": True, "outcome": "completed", "evidence_id": focus["provider_request_id"]},
        ],
        "evidence": evidence,
        "result": {**focus, "cases": verified_cases},
        "reason": reason,
        "next_check": "정상·위험 case의 requested·effective·Provider maxTokens를 순서대로 비교합니다.",
    }
