"""MCP Host adapter that runs the server-owned H22 verification cases."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from mcp import Client


MCP_URL = os.getenv("GUIDED_H22_MCP_URL", "http://guided-h22-mcp-server:8000/mcp")
CONTROL_TOKEN = os.environ["GUIDED_CONTROL_H22_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_H22_TOKEN"]
APPROVAL_SECRET = os.environ["GUIDED_H22_APPROVAL_SECRET"].encode()
DATABASE_PATH = os.getenv("GUIDED_H22_HOST_DATABASE", "/state/h22-host.sqlite3")
SERVER_ID = "training-notice-mcp"
PROTOCOL_VERSION = "2026-07-28"

Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        "CREATE TABLE IF NOT EXISTS receipts "
        "(suite_id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL)"
    )


def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_control(authorization: str | None = Header(default=None)) -> None:
    bearer(CONTROL_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


def canonical_digest(
    suite_id: str, call_id: str, trace_id: str, requester: str, notice: str
) -> str:
    payload = json.dumps(
        {
            "call_id": call_id,
            "notice": notice,
            "requester": requester,
            "suite_id": suite_id,
            "trace_id": trace_id,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def approve(
    suite_id: str,
    call_id: str,
    trace_id: str,
    requester: str,
    reviewer: str,
    notice: str,
    expires_at: int | None = None,
) -> str:
    if requester == reviewer:
        raise ValueError("self-approval-denied")
    claims = {
        "suite_id": suite_id,
        "requester": requester,
        "reviewer": reviewer,
        "server_id": SERVER_ID,
        "tool": "publish_notice",
        "args_sha256": canonical_digest(suite_id, call_id, trace_id, requester, notice),
        "expires_at": expires_at if expires_at is not None else int(time.time()) + 300,
        "nonce": secrets.token_hex(16),
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    signature = hmac.new(APPROVAL_SECRET, encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def result_summary(result) -> dict:
    return {
        "is_error": bool(result.is_error),
        "structured_content": tool_payload(result),
    }


def tool_payload(result) -> dict | None:
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
    return None


async def effect_count(client: Client, suite_id: str) -> int:
    result = await client.call_tool("audit_effects", {"suite_id": suite_id})
    payload = tool_payload(result)
    if result.is_error or not isinstance(payload, dict):
        raise RuntimeError("effect evidence unavailable")
    return int(payload["effects"])


app = FastAPI(title="H22 MCP Host Adapter", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    with connect() as database:
        database.execute("SELECT 1").fetchone()
    return {"status": "ready", "mcp_check": "not-run"}


@app.post("/v1/run-suite")
async def run_suite(_authorized: None = Depends(require_control)) -> dict:
    suite_id = str(uuid.uuid4())
    trace_id = secrets.token_hex(16)
    started_at = datetime.now(timezone.utc).isoformat()
    requester = "course-requester"
    reviewer = "course-reviewer"
    notice = "H22 훈련 공지"
    changed_notice = "승인하지 않은 변경 공지"

    async with Client(MCP_URL, mode=PROTOCOL_VERSION) as client:
        tools = await client.list_tools()
        inventory = sorted(tool.name for tool in tools.tools)
        inventory_digest = hashlib.sha256("\n".join(inventory).encode()).hexdigest()
        normal = await client.call_tool("lookup_notice", {"suite_id": suite_id})

        no_approval = await client.call_tool(
            "publish_notice",
            {
                "suite_id": suite_id,
                "call_id": str(uuid.uuid4()),
                "trace_id": trace_id,
                "requester": requester,
                "notice": notice,
                "approval_token": "",
            },
        )
        after_no_approval = await effect_count(client, suite_id)

        try:
            approve(suite_id, str(uuid.uuid4()), trace_id, requester, requester, notice)
            self_approval = {"denied": False, "reason": None}
        except ValueError as exc:
            self_approval = {"denied": True, "reason": str(exc)}

        approved_call_id = str(uuid.uuid4())
        approval_token = approve(
            suite_id, approved_call_id, trace_id, requester, reviewer, notice
        )
        changed = await client.call_tool(
            "publish_notice",
            {
                "suite_id": suite_id,
                "call_id": str(uuid.uuid4()),
                "trace_id": trace_id,
                "requester": requester,
                "notice": changed_notice,
                "approval_token": approval_token,
            },
        )
        after_changed = await effect_count(client, suite_id)
        expired_call_id = str(uuid.uuid4())
        expired_token = approve(
            suite_id,
            expired_call_id,
            trace_id,
            requester,
            reviewer,
            notice,
            expires_at=int(time.time()) - 1,
        )
        expired = await client.call_tool(
            "publish_notice",
            {
                "suite_id": suite_id,
                "call_id": expired_call_id,
                "trace_id": trace_id,
                "requester": requester,
                "notice": notice,
                "approval_token": expired_token,
            },
        )
        after_expired = await effect_count(client, suite_id)
        approved = await client.call_tool(
            "publish_notice",
            {
                "suite_id": suite_id,
                "call_id": approved_call_id,
                "trace_id": trace_id,
                "requester": requester,
                "notice": notice,
                "approval_token": approval_token,
            },
        )
        after_approved = await effect_count(client, suite_id)
        reused = await client.call_tool(
            "publish_notice",
            {
                "suite_id": suite_id,
                "call_id": approved_call_id,
                "trace_id": trace_id,
                "requester": requester,
                "notice": notice,
                "approval_token": approval_token,
            },
        )
        after_reuse = await effect_count(client, suite_id)
        build = await client.call_tool("server_build_info", {})

        receipt = {
            "suite_id": suite_id,
            "trace_id": trace_id,
            "started_at": started_at,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "protocol_version": client.protocol_version,
            "server_id": SERVER_ID,
            "tool_inventory": inventory,
            "tool_inventory_digest": inventory_digest,
            "normal": result_summary(normal),
            "no_approval": result_summary(no_approval),
            "self_approval": self_approval,
            "changed_args": result_summary(changed),
            "expired": result_summary(expired),
            "approved": result_summary(approved),
            "approved_call_id": approved_call_id,
            "reuse": result_summary(reused),
            "effect_counts": [
                after_no_approval,
                after_changed,
                after_expired,
                after_approved,
                after_reuse,
            ],
            "source_digest": (tool_payload(build) or {}).get("source_digest"),
            "external_action_called": False,
        }
    with connect() as database:
        database.execute(
            "INSERT INTO receipts VALUES(?,?)", (suite_id, json.dumps(receipt, ensure_ascii=False))
        )
    return {"suite_id": suite_id, "started_at": started_at}


@app.get("/v1/receipts/{suite_id}")
def receipt(suite_id: str, _authorized: None = Depends(require_verifier)) -> dict:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM receipts WHERE suite_id=?", (suite_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="receipt not found")
    return json.loads(row["receipt_json"])
