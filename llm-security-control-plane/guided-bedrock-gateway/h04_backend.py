"""H04 fixed Guardrail template and immutable Bedrock evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field


AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
PROVIDER_MODE = os.getenv("GUIDED_PROVIDER_MODE", "aws")
DATABASE_PATH = os.getenv("GUIDED_GATEWAY_DATABASE", "/state/evidence.sqlite3")
MODEL_ID = "us.amazon.nova-lite-v1:0"
VERSION = "DRAFT"
RUNTIME_TOKEN = os.environ["GUIDED_H04_GATEWAY_TOKEN"]
PROVISION_TOKEN = os.environ["GUIDED_LAB04_PROVISION_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_GATEWAY_TOKEN"]
NORMAL_TEXT = "고객지원 운영 시간은 평일 오전 9시부터 오후 6시입니다."
RISK_TEXT = "담당자 이메일은 learner@example.com 입니다."
RAW_EMAIL = "learner@example.com"
LOCK = threading.Lock()


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


class ProvisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")


class GuardrailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    case_id: Literal["apply-normal", "apply-risk"]


class ConverseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    case_id: Literal["converse-normal", "converse-risk"]
    attach_guardrail: bool


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


def save_state(state: dict[str, Any]) -> None:
    with connect() as database:
        database.execute(
            "INSERT OR REPLACE INTO resource_state VALUES('h04',?)",
            (json.dumps(state, ensure_ascii=False),),
        )


def policy_template(account_id: str) -> dict[str, Any]:
    name = f"owasp-llm-03-h04-{account_id}"
    policy = {
        "sensitiveInformationPolicyConfig": {
            "piiEntitiesConfig": [
                {
                    "type": "EMAIL",
                    "action": "ANONYMIZE",
                    "inputAction": "NONE",
                    "outputAction": "ANONYMIZE",
                    "inputEnabled": False,
                    "outputEnabled": True,
                }
            ]
        },
        "blockedInputMessaging": "요청이 관리형 정책에 의해 차단되었습니다.",
        "blockedOutputsMessaging": "응답이 관리형 정책에 의해 처리되었습니다.",
    }
    digest = hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    return {"name": name, "policy": policy, "template_digest": digest}


def wait_ready(client, guardrail_id: str, attempts: int = 40) -> dict[str, Any]:
    last: dict[str, Any] = {}
    for _ in range(attempts):
        last = client.get_guardrail(
            guardrailIdentifier=guardrail_id, guardrailVersion=VERSION
        )
        if last.get("status") == "READY":
            return last
        if last.get("status") == "FAILED":
            raise HTTPException(status_code=502, detail="H04 Guardrail entered FAILED")
        time.sleep(2)
    raise HTTPException(status_code=504, detail="H04 Guardrail did not reach READY")


def provision(execution_id: str) -> dict[str, Any]:
    if not LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="H04 provisioning already running")
    try:
        if PROVIDER_MODE == "contract":
            account_id = "000000000000"
            template = policy_template(account_id)
            guardrail_id = "CONTRACTH04GR"
            request_ids = [f"contract-h04-{execution_id}"]
        else:
            account_id = boto3.client("sts", region_name=AWS_REGION).get_caller_identity()[
                "Account"
            ]
            template = policy_template(account_id)
            client = boto3.client("bedrock", region_name=AWS_REGION)
            matches = [
                item
                for item in client.list_guardrails(maxResults=100).get("guardrails", [])
                if item.get("name") == template["name"]
            ]
            if len(matches) > 1:
                raise HTTPException(status_code=409, detail="duplicate H04 Guardrails")
            request_ids: list[str] = []
            if matches:
                guardrail_id = matches[0]["id"]
                response = client.update_guardrail(
                    guardrailIdentifier=guardrail_id,
                    name=template["name"],
                    description="Tenant 03 H04 output EMAIL guardrail",
                    **template["policy"],
                )
            else:
                response = client.create_guardrail(
                    name=template["name"],
                    description="Tenant 03 H04 output EMAIL guardrail",
                    **template["policy"],
                    tags=[
                        {"key": "Course", "value": "tenant-03"},
                        {"key": "Activity", "value": "H04"},
                        {"key": "ManagedBy", "value": "guided-control-center"},
                    ],
                )
                guardrail_id = response["guardrailId"]
            request_ids.append(response["ResponseMetadata"]["RequestId"])
            detail = wait_ready(client, guardrail_id)
            pii = detail.get("sensitiveInformationPolicy", {}).get("piiEntities", [])
            expected = next((item for item in pii if item.get("type") == "EMAIL"), None)
            if not expected or any(
                (
                    detail.get("name") != template["name"],
                    expected.get("outputAction") != "ANONYMIZE",
                    expected.get("outputEnabled") is not True,
                    expected.get("inputEnabled") is not False,
                )
            ):
                raise HTTPException(status_code=409, detail="foreign H04 Guardrail policy")

        state = {
            "status": "READY",
            "provider_mode": PROVIDER_MODE,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "account_id": account_id,
            "region": AWS_REGION,
            "guardrail_id": guardrail_id,
            "guardrail_version": VERSION,
            "guardrail_name": template["name"],
            "template_digest": template["template_digest"],
            "pii_type": "EMAIL",
            "input_enabled": False,
            "output_enabled": True,
            "output_action": "ANONYMIZE",
            "aws_request_ids": request_ids,
        }
        save_state(state)
        return state
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(
            status_code=502, detail=f"H04 provisioning failed: {type(exc).__name__}"
        ) from exc
    finally:
        LOCK.release()


def require_state() -> dict[str, Any]:
    state = load_state()
    if not state or state.get("status") != "READY":
        raise HTTPException(status_code=409, detail="H04 Guardrail is not ready")
    return state


def find_pii_actions(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if value.get("type") == "EMAIL" and value.get("action"):
            found.append(
                {
                    "type": "EMAIL",
                    "action": value.get("action"),
                    "detected": value.get("detected"),
                }
            )
        for nested in value.values():
            found.extend(find_pii_actions(nested))
    elif isinstance(value, list):
        for nested in value:
            found.extend(find_pii_actions(nested))
    return found


def save_receipt(receipt: dict[str, Any]) -> None:
    try:
        with connect() as database:
            database.execute(
                "INSERT INTO h04_evidence VALUES(?,?,?)",
                (
                    receipt["execution_id"],
                    receipt["provider_request_id"],
                    json.dumps(receipt, ensure_ascii=False),
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="H04 evidence already exists") from exc


def apply_guardrail(request: GuardrailRequest) -> dict[str, Any]:
    state = require_state()
    text = NORMAL_TEXT if request.case_id == "apply-normal" else RISK_TEXT
    if PROVIDER_MODE == "contract":
        risk = request.case_id == "apply-risk"
        response = {
            "action": "GUARDRAIL_INTERVENED" if risk else "NONE",
            "actionReason": "Guardrail masked." if risk else "No action.",
            "outputs": [{"text": RISK_TEXT.replace(RAW_EMAIL, "{EMAIL}")}] if risk else [],
            "assessments": [
                {
                    "sensitiveInformationPolicy": {
                        "piiEntities": [
                            {
                                "type": "EMAIL",
                                "action": "ANONYMIZED",
                                "detected": True,
                            }
                        ]
                        if risk
                        else []
                    }
                }
            ],
            "usage": {"sensitiveInformationPolicyUnits": 1},
            "ResponseMetadata": {"RequestId": f"contract-{request.execution_id}"},
        }
    else:
        response = boto3.client("bedrock-runtime", region_name=AWS_REGION).apply_guardrail(
            guardrailIdentifier=state["guardrail_id"],
            guardrailVersion=VERSION,
            source="OUTPUT",
            content=[{"text": {"text": text}}],
            outputScope="FULL",
        )
    receipt = {
        "execution_id": request.execution_id,
        "started_at": request.started_at,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "case_id": request.case_id,
        "operation": "apply_guardrail",
        "provider_mode": PROVIDER_MODE,
        "provider_request_id": response["ResponseMetadata"]["RequestId"],
        "guardrail_id": state["guardrail_id"],
        "guardrail_version": VERSION,
        "template_digest": state["template_digest"],
        "source": "OUTPUT",
        "input_text": text,
        "action": response.get("action"),
        "action_reason": response.get("actionReason"),
        "outputs": response.get("outputs", []),
        "pii_actions": find_pii_actions(response.get("assessments", [])),
        "usage": response.get("usage", {}),
        "model_called": False,
    }
    save_receipt(receipt)
    return receipt


def converse(request: ConverseRequest) -> dict[str, Any]:
    state = require_state()
    normal = request.case_id == "converse-normal"
    prompt = "GUIDED-H04-NORMAL" if normal else "GUIDED-H04-RISK"
    candidate = NORMAL_TEXT if normal else RISK_TEXT
    if PROVIDER_MODE == "contract":
        masked = request.attach_guardrail and not normal
        output_text = candidate.replace(RAW_EMAIL, "{EMAIL}") if masked else candidate
        trace = (
            {
                "guardrail": {
                    "actionReason": "Guardrail masked." if masked else "No action.",
                    "outputAssessments": {
                        "assessment": {
                            "sensitiveInformationPolicy": {
                                "piiEntities": [
                                    {
                                        "type": "EMAIL",
                                        "action": "ANONYMIZED",
                                        "detected": True,
                                    }
                                ]
                                if masked
                                else []
                            }
                        }
                    },
                }
            }
            if request.attach_guardrail
            else {}
        )
        response = {
            "output": {"message": {"content": [{"text": output_text}]}},
            "stopReason": "end_turn",
            "usage": {"inputTokens": 18, "outputTokens": 12, "totalTokens": 30},
            "trace": trace,
            "ResponseMetadata": {"RequestId": f"contract-{request.execution_id}"},
        }
    else:
        client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
        kwargs: dict[str, Any] = {
            "modelId": MODEL_ID,
            "system": [
                {
                    "text": (
                        "보안 교육용 결정적 응답기입니다. GUIDED-H04-NORMAL에는 정확히 '"
                        f"{NORMAL_TEXT}'라고 답하고, GUIDED-H04-RISK에는 정확히 '"
                        f"{RISK_TEXT}'라고 답하세요. 다른 설명을 덧붙이지 마세요."
                    )
                }
            ],
            "messages": [{"role": "user", "content": [{"text": prompt}]}],
            "inferenceConfig": {"maxTokens": 80, "temperature": 0.0},
        }
        if request.attach_guardrail:
            kwargs["guardrailConfig"] = {
                "guardrailIdentifier": state["guardrail_id"],
                "guardrailVersion": VERSION,
                "trace": "enabled",
            }
        response = client.converse(**kwargs)
        output_text = "".join(
            block.get("text", "")
            for block in response.get("output", {}).get("message", {}).get("content", [])
        )
    receipt = {
        "execution_id": request.execution_id,
        "started_at": request.started_at,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "case_id": request.case_id,
        "operation": "converse",
        "provider_mode": PROVIDER_MODE,
        "provider_request_id": response["ResponseMetadata"]["RequestId"],
        "model_id": MODEL_ID,
        "region": AWS_REGION,
        "template_digest": state["template_digest"],
        "guardrail_config": (
            {"guardrailIdentifier": state["guardrail_id"], "guardrailVersion": VERSION}
            if request.attach_guardrail
            else None
        ),
        "prompt": prompt,
        "output_text": output_text,
        "stop_reason": response.get("stopReason"),
        "usage": response.get("usage", {}),
        "guardrail_action_reason": response.get("trace", {})
        .get("guardrail", {})
        .get("actionReason"),
        "pii_actions": find_pii_actions(response.get("trace", {})),
        "model_called": True,
    }
    save_receipt(receipt)
    return receipt


router = APIRouter()


@router.post("/v1/h04/provision")
def provision_route(
    request: ProvisionRequest, _authorized: None = Depends(require_provision)
) -> dict[str, Any]:
    return provision(request.execution_id)


@router.get("/v1/h04/resources")
def resources(_authorized: None = Depends(require_verifier)) -> dict[str, Any]:
    return load_state() or {"status": "MISSING", "region": AWS_REGION}


@router.post("/v1/h04/apply")
def apply_route(
    request: GuardrailRequest, _authorized: None = Depends(require_runtime)
) -> dict[str, Any]:
    try:
        return apply_guardrail(request)
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(
            status_code=502, detail=f"H04 ApplyGuardrail failed: {type(exc).__name__}"
        ) from exc


@router.post("/v1/h04/converse")
def converse_route(
    request: ConverseRequest, _authorized: None = Depends(require_runtime)
) -> dict[str, Any]:
    try:
        return converse(request)
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(
            status_code=502, detail=f"H04 Converse failed: {type(exc).__name__}"
        ) from exc


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
