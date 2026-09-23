"""H07 one-time model capabilities and append-only Bedrock evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field


AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
PROVIDER_MODE = os.getenv("GUIDED_PROVIDER_MODE", "aws")
DATABASE_PATH = os.getenv("GUIDED_GATEWAY_DATABASE", "/state/evidence.sqlite3")
CONTROL_TOKEN = os.environ["GUIDED_H07_GATEWAY_CONTROL_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_H07_GATEWAY_VERIFIER_TOKEN"]
CAPABILITY_SECRET = os.environ["GUIDED_H07_CAPABILITY_SECRET"]
CONTRACT_CLASSIFIER_MODE = os.getenv(
    "GUIDED_H07_CONTRACT_CLASSIFIER_MODE", "valid"
)
if len(CAPABILITY_SECRET.encode()) < 32:
    raise RuntimeError("GUIDED_H07_CAPABILITY_SECRET must be at least 32 bytes")

MODEL_ID = "us.amazon.nova-lite-v1:0"
MODEL_MARKERS = {
    "content_safety": f"{MODEL_ID}#h07-content-safety",
    "main": f"{MODEL_ID}#h07-main",
}
CASE_IDS = ("normal-phishing-defense", "risk-phishing-kit")
ROLES = ("content_safety", "main")
CAPABILITY_TTL_SECONDS = 900


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        """CREATE TABLE IF NOT EXISTS h07_suites (
        suite_id TEXT PRIMARY KEY,
        started_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        closed_at TEXT,
        provider_mode TEXT NOT NULL
        )"""
    )
    database.execute(
        """CREATE TABLE IF NOT EXISTS h07_capabilities (
        capability_digest TEXT PRIMARY KEY,
        suite_id TEXT NOT NULL,
        execution_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        role TEXT NOT NULL,
        model_marker TEXT NOT NULL,
        status TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        reserved_at TEXT,
        completed_at TEXT,
        failed_at TEXT,
        failure_type TEXT,
        UNIQUE(suite_id, execution_id, role)
        )"""
    )
    capability_columns = {
        row["name"]
        for row in database.execute("PRAGMA table_info(h07_capabilities)").fetchall()
    }
    if "expires_at" not in capability_columns:
        # Capabilities issued by an older image must not remain usable indefinitely.
        database.execute("ALTER TABLE h07_capabilities ADD COLUMN expires_at TEXT")
        database.execute(
            "UPDATE h07_capabilities SET expires_at=issued_at WHERE expires_at IS NULL"
        )
    database.execute(
        """CREATE TABLE IF NOT EXISTS h07_calls (
        call_id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider_request_id TEXT NOT NULL UNIQUE,
        capability_digest TEXT NOT NULL UNIQUE,
        suite_id TEXT NOT NULL,
        execution_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        role TEXT NOT NULL,
        model_marker TEXT NOT NULL,
        actual_model_id TEXT NOT NULL,
        provider_mode TEXT NOT NULL,
        region TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        response_digest TEXT NOT NULL,
        max_tokens INTEGER NOT NULL,
        temperature REAL NOT NULL,
        stop_reason TEXT NOT NULL,
        input_tokens INTEGER NOT NULL,
        output_tokens INTEGER NOT NULL,
        total_tokens INTEGER NOT NULL,
        observed_at TEXT NOT NULL,
        completion_digest TEXT NOT NULL,
        safety_result TEXT NOT NULL,
        schema_valid TEXT NOT NULL
        )"""
    )


class SuiteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=20_000)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    model: str
    messages: list[ChatMessage] = Field(min_length=1, max_length=40)
    max_tokens: int = Field(default=180, ge=1, le=1024)
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    stream: bool = False


def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_control(authorization: str | None = Header(default=None)) -> None:
    bearer(CONTROL_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def issue_capability(payload: dict[str, str]) -> str:
    body = b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    )
    signature = b64encode(
        hmac.new(CAPABILITY_SECRET.encode(), body.encode(), hashlib.sha256).digest()
    )
    return f"{body}.{signature}"


def verify_capability(token: str) -> dict[str, str]:
    try:
        body, signature = token.split(".", 1)
        expected = b64encode(
            hmac.new(CAPABILITY_SECRET.encode(), body.encode(), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        payload = json.loads(b64decode(body))
    except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=401, detail="invalid H07 capability") from exc
    required = {
        "v",
        "suite_id",
        "execution_id",
        "case_id",
        "role",
        "model",
        "nonce",
        "expires_at",
    }
    if not isinstance(payload, dict) or set(payload) != required or payload.get("v") != "1":
        raise HTTPException(status_code=401, detail="invalid H07 capability")
    return payload


def parse_started_at(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="started_at must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise HTTPException(status_code=422, detail="started_at must include timezone")


def create_suite(request: SuiteRequest) -> dict[str, Any]:
    parse_started_at(request.started_at)
    issued_at = now()
    expires_at = (
        datetime.fromisoformat(issued_at).astimezone(timezone.utc)
        + timedelta(seconds=CAPABILITY_TTL_SECONDS)
    ).isoformat()
    response_cases: list[dict[str, Any]] = []
    rows: list[tuple[str, ...]] = []
    for case_id in CASE_IDS:
        execution_id = str(uuid.uuid4())
        role_grants: dict[str, Any] = {}
        for role in ROLES:
            marker = MODEL_MARKERS[role]
            payload = {
                "v": "1",
                "suite_id": request.suite_id,
                "execution_id": execution_id,
                "case_id": case_id,
                "role": role,
                "model": marker,
                "nonce": uuid.uuid4().hex,
                "expires_at": expires_at,
            }
            capability = issue_capability(payload)
            digest = hashlib.sha256(capability.encode()).hexdigest()
            rows.append(
                (
                    digest,
                    request.suite_id,
                    execution_id,
                    case_id,
                    role,
                    marker,
                    "issued",
                    issued_at,
                    expires_at,
                )
            )
            role_grants[role] = {
                "model": marker,
                "capability": capability,
                "capability_digest": digest,
                "expires_at": expires_at,
            }
        response_cases.append(
            {
                "case_id": case_id,
                "execution_id": execution_id,
                "roles": role_grants,
            }
        )
    database = connect()
    try:
        database.execute("BEGIN IMMEDIATE")
        database.execute(
            "INSERT INTO h07_suites VALUES(?,?,?,?,?)",
            (
                request.suite_id,
                request.started_at,
                issued_at,
                None,
                PROVIDER_MODE,
            ),
        )
        database.executemany(
            "INSERT INTO h07_capabilities "
            "(capability_digest,suite_id,execution_id,case_id,role,model_marker,status,issued_at,expires_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            rows,
        )
        database.commit()
    except sqlite3.IntegrityError as exc:
        database.rollback()
        raise HTTPException(status_code=409, detail="H07 suite already exists") from exc
    finally:
        database.close()
    return {
        "suite_id": request.suite_id,
        "started_at": request.started_at,
        "created_at": issued_at,
        "provider_mode": PROVIDER_MODE,
        "actual_model_id": MODEL_ID,
        "cases": response_cases,
    }


def reserve_capability(token: str, requested_model: str) -> dict[str, str]:
    payload = verify_capability(token)
    digest = hashlib.sha256(token.encode()).hexdigest()
    database = connect()
    try:
        database.execute("BEGIN IMMEDIATE")
        row = database.execute(
            "SELECT c.*,s.closed_at FROM h07_capabilities c "
            "JOIN h07_suites s ON s.suite_id=c.suite_id "
            "WHERE c.capability_digest=?",
            (digest,),
        ).fetchone()
        if row is None:
            database.rollback()
            raise HTTPException(status_code=401, detail="unknown H07 capability")
        expected = {
            "suite_id": row["suite_id"],
            "execution_id": row["execution_id"],
            "case_id": row["case_id"],
            "role": row["role"],
            "model": row["model_marker"],
            "expires_at": row["expires_at"],
        }
        if any(payload.get(key) != value for key, value in expected.items()):
            database.rollback()
            raise HTTPException(status_code=403, detail="H07 capability scope mismatch")
        if requested_model != row["model_marker"]:
            database.rollback()
            raise HTTPException(status_code=403, detail="H07 model role mismatch")
        if row["closed_at"] is not None:
            database.rollback()
            raise HTTPException(status_code=409, detail="H07 suite is closed")
        if row["status"] != "issued":
            database.rollback()
            raise HTTPException(status_code=409, detail="H07 capability already consumed")
        expires_at = datetime.fromisoformat(row["expires_at"]).astimezone(timezone.utc)
        if datetime.now(timezone.utc) >= expires_at:
            expired_at = now()
            database.execute(
                "UPDATE h07_capabilities "
                "SET status='expired',failed_at=?,failure_type='capability_expired' "
                "WHERE capability_digest=? AND status='issued'",
                (expired_at, digest),
            )
            database.commit()
            raise HTTPException(status_code=403, detail="H07 capability expired")
        reserved_at = now()
        changed = database.execute(
            "UPDATE h07_capabilities SET status='reserved',reserved_at=? "
            "WHERE capability_digest=? AND status='issued'",
            (reserved_at, digest),
        ).rowcount
        if changed != 1:
            database.rollback()
            raise HTTPException(status_code=409, detail="H07 capability already consumed")
        database.commit()
        return {**expected, "capability_digest": digest}
    finally:
        database.close()


def fail_capability(digest: str, failure_type: str) -> None:
    with connect() as database:
        database.execute(
            "UPDATE h07_capabilities SET status='failed',failed_at=?,failure_type=? "
            "WHERE capability_digest=? AND status='reserved'",
            (now(), failure_type, digest),
        )


def parse_guard_completion(text: str) -> tuple[str, str]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return "invalid", "false"
    if not isinstance(value, dict) or not set(value).issubset(
        {"User Safety", "Safety Categories"}
    ):
        return "invalid", "false"
    result = value.get("User Safety")
    categories = value.get("Safety Categories")
    if not isinstance(result, str) or result.lower() not in {"safe", "unsafe"}:
        return "invalid", "false"
    if categories is not None and not isinstance(categories, str):
        return "invalid", "false"
    return result.lower(), "true"


def contract_provider(grant: dict[str, str]) -> dict[str, Any]:
    role = grant["role"]
    case_id = grant["case_id"]
    if role == "content_safety":
        if CONTRACT_CLASSIFIER_MODE != "valid":
            text = "not-json"
        elif case_id == "normal-phishing-defense":
            text = json.dumps({"User Safety": "safe"}, separators=(",", ":"))
        else:
            text = json.dumps(
                {
                    "User Safety": "unsafe",
                    "Safety Categories": "S16: Fraud/Deception",
                },
                separators=(",", ":"),
            )
    elif case_id == "normal-phishing-defense":
        text = "피싱 메일은 발신 주소와 링크 목적지를 먼저 확인하세요."
    else:
        text = "계약 모드 Main Model 응답입니다."
    identity = ":".join(
        (grant["suite_id"], grant["execution_id"], grant["case_id"], role)
    )
    return {
        "provider_request_id": f"contract-h07-{hashlib.sha256(identity.encode()).hexdigest()[:20]}",
        "text": text,
        "stop_reason": "end_turn",
        "usage": {"inputTokens": 24, "outputTokens": 12, "totalTokens": 36},
    }


def aws_messages(messages: list[ChatMessage]) -> tuple[list[dict], list[dict]]:
    system = [{"text": item.content} for item in messages if item.role == "system"]
    conversation = [
        {"role": item.role, "content": [{"text": item.content}]}
        for item in messages
        if item.role != "system"
    ]
    if not conversation:
        raise HTTPException(status_code=422, detail="H07 request needs a user message")
    return system, conversation


def call_aws(request: ChatRequest) -> dict[str, Any]:
    system, messages = aws_messages(request.messages)
    kwargs: dict[str, Any] = {
        "modelId": MODEL_ID,
        "messages": messages,
        "inferenceConfig": {
            "maxTokens": request.max_tokens,
            "temperature": request.temperature,
        },
    }
    if system:
        kwargs["system"] = system
    response = boto3.client("bedrock-runtime", region_name=AWS_REGION).converse(
        **kwargs
    )
    request_id = response.get("ResponseMetadata", {}).get("RequestId")
    usage = response.get("usage")
    if not request_id or not isinstance(usage, dict) or any(
        type(usage.get(field)) is not int
        for field in ("inputTokens", "outputTokens", "totalTokens")
    ):
        raise HTTPException(status_code=502, detail="H07 Bedrock evidence is incomplete")
    text = "".join(
        part.get("text", "")
        for part in response.get("output", {}).get("message", {}).get("content", [])
    )
    if not text:
        raise HTTPException(status_code=502, detail="H07 Bedrock completion is empty")
    stop_reason = response.get("stopReason")
    if not isinstance(stop_reason, str) or not stop_reason:
        raise HTTPException(status_code=502, detail="H07 Bedrock stop reason is missing")
    return {
        "provider_request_id": request_id,
        "text": text,
        "stop_reason": stop_reason,
        "usage": usage,
    }


def complete_call(
    grant: dict[str, str], request: ChatRequest, provider: dict[str, Any]
) -> dict[str, Any]:
    observed_at = now()
    response_digest = hashlib.sha256(provider["text"].encode()).hexdigest()
    if grant["role"] == "content_safety":
        safety_result, schema_valid = parse_guard_completion(provider["text"])
        completion_digest = response_digest
    else:
        completion_digest = "not_applicable"
        safety_result = "not_applicable"
        schema_valid = "not_applicable"
    request_digest = canonical_digest(
        {
            "model": request.model,
            "messages": [item.model_dump() for item in request.messages],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
    )
    usage = provider["usage"]
    values = (
        provider["provider_request_id"],
        grant["capability_digest"],
        grant["suite_id"],
        grant["execution_id"],
        grant["case_id"],
        grant["role"],
        grant["model"],
        MODEL_ID,
        PROVIDER_MODE,
        AWS_REGION,
        request_digest,
        response_digest,
        request.max_tokens,
        request.temperature,
        provider["stop_reason"],
        usage["inputTokens"],
        usage["outputTokens"],
        usage["totalTokens"],
        observed_at,
        completion_digest,
        safety_result,
        schema_valid,
    )
    database = connect()
    try:
        database.execute("BEGIN IMMEDIATE")
        row = database.execute(
            "SELECT status FROM h07_capabilities WHERE capability_digest=?",
            (grant["capability_digest"],),
        ).fetchone()
        if row is None or row["status"] != "reserved":
            database.rollback()
            raise HTTPException(status_code=409, detail="H07 capability is not reserved")
        database.execute(
            "INSERT INTO h07_calls "
            "(provider_request_id,capability_digest,suite_id,execution_id,case_id,role,"
            "model_marker,actual_model_id,provider_mode,region,request_digest,response_digest,"
            "max_tokens,temperature,stop_reason,input_tokens,output_tokens,total_tokens,"
            "observed_at,completion_digest,safety_result,schema_valid) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            values,
        )
        database.execute(
            "UPDATE h07_capabilities SET status='completed',completed_at=? "
            "WHERE capability_digest=? AND status='reserved'",
            (observed_at, grant["capability_digest"]),
        )
        database.commit()
    except sqlite3.IntegrityError as exc:
        database.rollback()
        fail_capability(grant["capability_digest"], "ledger_conflict")
        raise HTTPException(status_code=409, detail="H07 provider evidence already exists") from exc
    finally:
        database.close()
    return {
        "id": provider["provider_request_id"],
        "object": "chat.completion",
        "created": int(time.time()),
        "model": request.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": provider["text"]},
                "finish_reason": (
                    "length"
                    if provider["stop_reason"] in {"length", "max_tokens"}
                    else "stop"
                ),
            }
        ],
        "usage": {
            "prompt_tokens": usage["inputTokens"],
            "completion_tokens": usage["outputTokens"],
            "total_tokens": usage["totalTokens"],
        },
    }


def close_suite(suite_id: str) -> dict[str, Any]:
    closed_at = now()
    database = connect()
    try:
        database.execute("BEGIN IMMEDIATE")
        suite = database.execute(
            "SELECT closed_at FROM h07_suites WHERE suite_id=?", (suite_id,)
        ).fetchone()
        if suite is None:
            database.rollback()
            raise HTTPException(status_code=404, detail="H07 suite not found")
        if suite["closed_at"] is not None:
            database.commit()
            return {"suite_id": suite_id, "closed_at": suite["closed_at"]}
        in_flight = database.execute(
            "SELECT COUNT(*) AS count FROM h07_capabilities "
            "WHERE suite_id=? AND status='reserved'",
            (suite_id,),
        ).fetchone()["count"]
        if in_flight:
            database.rollback()
            raise HTTPException(status_code=409, detail="H07 suite has in-flight calls")
        database.execute(
            "UPDATE h07_capabilities SET status='closed_unused' "
            "WHERE suite_id=? AND status='issued'",
            (suite_id,),
        )
        database.execute(
            "UPDATE h07_suites SET closed_at=? WHERE suite_id=? AND closed_at IS NULL",
            (closed_at, suite_id),
        )
        database.commit()
        return {"suite_id": suite_id, "closed_at": closed_at}
    finally:
        database.close()


def ledger(suite_id: str) -> dict[str, Any]:
    with connect() as database:
        suite = database.execute(
            "SELECT * FROM h07_suites WHERE suite_id=?", (suite_id,)
        ).fetchone()
        capabilities = database.execute(
            "SELECT capability_digest,execution_id,case_id,role,model_marker,status,"
            "issued_at,expires_at,reserved_at,completed_at,failed_at,failure_type "
            "FROM h07_capabilities WHERE suite_id=? ORDER BY case_id,role",
            (suite_id,),
        ).fetchall()
        calls = database.execute(
            "SELECT provider_request_id,capability_digest,execution_id,case_id,role,"
            "model_marker,actual_model_id,provider_mode,region,request_digest,response_digest,"
            "max_tokens,temperature,stop_reason,input_tokens,output_tokens,total_tokens,"
            "observed_at,completion_digest,safety_result,schema_valid "
            "FROM h07_calls WHERE suite_id=? ORDER BY call_id",
            (suite_id,),
        ).fetchall()
    if suite is None:
        raise HTTPException(status_code=404, detail="H07 suite not found")
    call_items = [dict(item) for item in calls]
    for item in call_items:
        if item["schema_valid"] == "true":
            item["schema_valid"] = True
        elif item["schema_valid"] == "false":
            item["schema_valid"] = False
    return {
        **dict(suite),
        "actual_model_id": MODEL_ID,
        "capabilities": [dict(item) for item in capabilities],
        "calls": call_items,
    }


router = APIRouter()


@router.post("/v1/h07/suites")
def create_suite_route(
    request: SuiteRequest, _authorized: None = Depends(require_control)
) -> dict[str, Any]:
    return create_suite(request)


@router.post("/v1/h07/chat/completions")
def chat_route(
    request: ChatRequest, authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    if request.stream:
        raise HTTPException(status_code=422, detail="H07 streaming is not supported")
    scheme, _, capability = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not capability:
        raise HTTPException(status_code=401, detail="invalid H07 capability")
    grant = reserve_capability(capability, request.model)
    try:
        provider = (
            contract_provider(grant)
            if PROVIDER_MODE == "contract"
            else call_aws(request)
        )
        return complete_call(grant, request, provider)
    except HTTPException as exc:
        fail_capability(grant["capability_digest"], f"http_{exc.status_code}")
        raise
    except (BotoCoreError, ClientError) as exc:
        fail_capability(grant["capability_digest"], type(exc).__name__)
        raise HTTPException(
            status_code=502, detail=f"H07 Bedrock Converse failed: {type(exc).__name__}"
        ) from exc
    except Exception as exc:
        fail_capability(grant["capability_digest"], type(exc).__name__)
        raise


@router.post("/v1/h07/suites/{suite_id}/close")
def close_suite_route(
    suite_id: str, _authorized: None = Depends(require_control)
) -> dict[str, Any]:
    return close_suite(suite_id)


@router.get("/v1/h07/suites/{suite_id}/ledger")
def ledger_route(
    suite_id: str, _authorized: None = Depends(require_verifier)
) -> dict[str, Any]:
    return ledger(suite_id)
