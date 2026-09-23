"""Agent Host that runs the server-owned H21 model, MCP, and budget suite."""

from __future__ import annotations

import base64
import asyncio
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from mcp import Client

from policy import PolicyDenied, authorize


CONTROL_TOKEN = os.environ["GUIDED_CONTROL_H21_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_H21_TOKEN"]
PROVIDER_TOKEN = os.environ["GUIDED_H21_PROVIDER_TOKEN"]
OAUTH_SECRET = os.environ["GUIDED_H21_OAUTH_SECRET"].encode()
PROVIDER_URL = os.getenv("GUIDED_H21_PROVIDER_URL", "http://guided-h21-provider:8000")
SERVER_URLS = {
    "training-notice-mcp": os.getenv(
        "GUIDED_H21_TRUSTED_MCP_URL", "http://guided-h21-trusted-mcp:8000/mcp"
    ),
    "untrusted-notice-mcp": os.getenv(
        "GUIDED_H21_UNTRUSTED_MCP_URL", "http://guided-h21-untrusted-mcp:8000/mcp"
    ),
}
PROTOCOL = "2026-07-28"
MODEL = "us.amazon.nova-lite-v1:0"
RECEIPTS: dict[str, dict] = {}


def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_control(authorization: str | None = Header(default=None)) -> None:
    bearer(CONTROL_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


def access_token(subject: str, audience: str) -> str:
    claims = {
        "issuer": "https://training-idp.local",
        "audience": audience,
        "scope": "tools:read",
        "subject": subject,
        "expires_at": int(time.time()) + 300,
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    signature = hmac.new(OAUTH_SECRET, encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def tool_payload(result) -> dict:
    if isinstance(result.structured_content, dict):
        return result.structured_content
    for block in result.content:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
    return {}


async def provider_call(suite_id: str, case_id: str, trace_id: str, principal: str, model: str, stage: str) -> dict:
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.post(
            f"{PROVIDER_URL}/v1/generate",
            json={
                "suite_id": suite_id,
                "case_id": case_id,
                "trace_id": trace_id,
                "principal": principal,
                "model": model,
                "stage": stage,
            },
            headers={"Authorization": f"Bearer {PROVIDER_TOKEN}"},
        )
    response.raise_for_status()
    return response.json()


CASES = [
    {"case_id": "normal", "model": MODEL, "server_id": "training-notice-mcp", "tool": "lookup_notice", "calls": 1, "bytes": 16, "owner": "support-agent"},
    {"case_id": "forbidden-model", "model": "attacker-selected-model", "server_id": "training-notice-mcp", "tool": "lookup_notice", "calls": 1, "bytes": 16, "owner": "support-agent"},
    {"case_id": "untrusted-server", "model": MODEL, "server_id": "untrusted-notice-mcp", "tool": "lookup_notice", "calls": 1, "bytes": 16, "owner": "support-agent"},
    {"case_id": "forbidden-tool", "model": MODEL, "server_id": "training-notice-mcp", "tool": "debug_dump", "calls": 1, "bytes": 16, "owner": "support-agent"},
    {"case_id": "tool-loop", "model": MODEL, "server_id": "training-notice-mcp", "tool": "lookup_notice", "calls": 3, "bytes": 16, "owner": "support-agent"},
    {"case_id": "oversized-result", "model": MODEL, "server_id": "training-notice-mcp", "tool": "oversized_context", "calls": 1, "bytes": 96, "owner": "support-agent"},
    {"case_id": "tool-timeout", "model": MODEL, "server_id": "training-notice-mcp", "tool": "slow_context", "calls": 1, "bytes": 16, "owner": "support-agent", "timeout_ms": 1000},
    {"case_id": "foreign-state", "model": MODEL, "server_id": "training-notice-mcp", "tool": "lookup_notice", "calls": 1, "bytes": 16, "owner": "other-agent"},
    {"case_id": "wrong-audience", "model": MODEL, "server_id": "training-notice-mcp", "tool": "lookup_notice", "calls": 1, "bytes": 16, "owner": "support-agent", "audience": "another-resource"},
]


async def run_case(suite_id: str, definition: dict) -> dict:
    trace_id = secrets.token_hex(16)
    principal = "support-agent"
    try:
        admission = authorize(
            principal,
            definition["model"],
            definition["server_id"],
            definition["tool"],
            definition["calls"],
            4096,
            definition.get("timeout_ms", 1000),
            definition["owner"],
        )
    except (KeyError, PolicyDenied) as exc:
        return {"case_id": definition["case_id"], "trace_id": trace_id, "decision": "block", "reason": str(exc), "provider_calls": 0, "tool_calls": 0}

    provider_calls = 0
    tool_calls = 0
    await provider_call(suite_id, definition["case_id"], trace_id, principal, admission.model, "proposal")
    provider_calls += 1
    token = access_token(principal, definition.get("audience", admission.server_id))
    last_payload: dict = {}
    mcp_error = False
    async with Client(SERVER_URLS[admission.server_id], mode=PROTOCOL) as client:
        for _ in range(min(definition["calls"], admission.max_tool_calls)):
            try:
                result = await asyncio.wait_for(
                    client.call_tool(
                        admission.tool,
                        {
                            "suite_id": suite_id,
                            "case_id": definition["case_id"],
                            "trace_id": trace_id,
                            "access_token": token,
                            "state_owner": definition["owner"],
                            "payload_bytes": definition["bytes"],
                        },
                    ),
                    timeout=admission.tool_timeout_ms / 1000,
                )
            except TimeoutError:
                return {"case_id": definition["case_id"], "trace_id": trace_id, "decision": "block", "reason": "tool-timeout", "provider_calls": provider_calls, "tool_calls": tool_calls + 1}
            tool_calls += 1
            mcp_error = mcp_error or bool(result.is_error)
            last_payload = tool_payload(result)
            if result.is_error:
                break
    if mcp_error:
        return {"case_id": definition["case_id"], "trace_id": trace_id, "decision": "block", "reason": "mcp-server-denied", "provider_calls": provider_calls, "tool_calls": tool_calls}
    if definition["calls"] > admission.max_tool_calls:
        return {"case_id": definition["case_id"], "trace_id": trace_id, "decision": "block", "reason": "tool-call-budget", "provider_calls": provider_calls, "tool_calls": tool_calls}
    result_bytes = len(json.dumps(last_payload, ensure_ascii=False, separators=(",", ":")).encode())
    if result_bytes > admission.max_result_bytes:
        return {"case_id": definition["case_id"], "trace_id": trace_id, "decision": "block", "reason": "tool-result-byte-limit", "provider_calls": provider_calls, "tool_calls": tool_calls, "result_bytes": result_bytes}
    await provider_call(suite_id, definition["case_id"], trace_id, principal, admission.model, "final")
    provider_calls += 1
    return {"case_id": definition["case_id"], "trace_id": trace_id, "decision": "allow", "reason": None, "provider_calls": provider_calls, "tool_calls": tool_calls, "result_bytes": result_bytes}


app = FastAPI(title="H21 Agent Gateway Host", docs_url=None, redoc_url=None)


@app.get("/readyz")
def readyz() -> dict:
    return {"status": "ready", "protocol_version": PROTOCOL}


@app.post("/v1/run-suite")
async def run_suite(_authorized: None = Depends(require_control)) -> dict:
    suite_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    cases = [await run_case(suite_id, definition) for definition in CASES]
    receipt = {
        "suite_id": suite_id,
        "started_at": started_at,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "protocol_version": PROTOCOL,
        "source_digest": hashlib.sha256(Path("/app/policy.py").read_bytes()).hexdigest(),
        "cases": cases,
        "external_action_called": False,
    }
    RECEIPTS[suite_id] = receipt
    return {"suite_id": suite_id, "started_at": started_at}


@app.get("/v1/receipts/{suite_id}")
def receipt(suite_id: str, _authorized: None = Depends(require_verifier)) -> dict:
    if suite_id not in RECEIPTS:
        raise HTTPException(status_code=404, detail="receipt not found")
    return RECEIPTS[suite_id]
