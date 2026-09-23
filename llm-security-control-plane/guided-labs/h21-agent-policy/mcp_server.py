"""H21 MCP Server with synthetic OAuth claim and state-owner validation."""

from __future__ import annotations

import base64
import asyncio
import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings


SERVER_ID = os.environ["GUIDED_H21_SERVER_ID"]
SERVICE_HOST = os.environ["GUIDED_H21_SERVICE_HOST"]
TOKEN_SECRET = os.environ["GUIDED_H21_OAUTH_SECRET"].encode()
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_H21_TOKEN"]
PROTOCOL = "2026-07-28"
CALLS: list[dict] = []
LOCK = threading.Lock()
mcp = MCPServer(SERVER_ID)


def decode_token(token: str) -> dict:
    encoded, separator, signature = token.partition(".")
    expected = hmac.new(TOKEN_SECRET, encoded.encode(), hashlib.sha256).hexdigest()
    if not separator or not hmac.compare_digest(signature, expected):
        raise ToolError("oauth-token-invalid")
    padding = "=" * (-len(encoded) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded + padding))


def authorize(token: str, state_owner: str) -> str:
    claims = decode_token(token)
    if claims.get("issuer") != "https://training-idp.local":
        raise ToolError("oauth-issuer-invalid")
    if claims.get("audience") != SERVER_ID:
        raise ToolError("oauth-audience-invalid")
    if "tools:read" not in claims.get("scope", "").split():
        raise ToolError("oauth-scope-missing")
    if int(claims.get("expires_at", 0)) <= int(time.time()):
        raise ToolError("oauth-token-expired")
    if claims.get("subject") != state_owner:
        raise ToolError("state-owner-mismatch")
    return claims["subject"]


def record(suite_id: str, case_id: str, trace_id: str, tool: str, outcome: str) -> None:
    with LOCK:
        CALLS.append(
            {
                "suite_id": suite_id,
                "case_id": case_id,
                "trace_id": trace_id,
                "server_id": SERVER_ID,
                "tool": tool,
                "outcome": outcome,
            }
        )


def execute_read(
    tool: str,
    suite_id: str,
    case_id: str,
    trace_id: str,
    access_token: str,
    state_owner: str,
    payload_bytes: int,
) -> dict:
    try:
        principal = authorize(access_token, state_owner)
    except ToolError as exc:
        record(suite_id, case_id, trace_id, tool, "denied")
        raise exc
    record(suite_id, case_id, trace_id, tool, "allowed")
    return {
        "principal": principal,
        "server_id": SERVER_ID,
        "payload": "x" * payload_bytes,
        "external_action_called": False,
    }


@mcp.tool()
def lookup_notice(
    suite_id: str,
    case_id: str,
    trace_id: str,
    access_token: str,
    state_owner: str,
    payload_bytes: int = 16,
) -> dict:
    """Return a bounded local notice fixture."""
    return execute_read(
        "lookup_notice", suite_id, case_id, trace_id, access_token, state_owner, payload_bytes
    )


@mcp.tool()
def oversized_context(
    suite_id: str,
    case_id: str,
    trace_id: str,
    access_token: str,
    state_owner: str,
    payload_bytes: int = 96,
) -> dict:
    """Return a deliberately oversized Tool result for the Host limit."""
    return execute_read(
        "oversized_context", suite_id, case_id, trace_id, access_token, state_owner, payload_bytes
    )


@mcp.tool()
def debug_dump(
    suite_id: str,
    case_id: str,
    trace_id: str,
    access_token: str,
    state_owner: str,
    payload_bytes: int = 16,
) -> dict:
    """Return synthetic debug data that the trusted Host must not expose."""
    return execute_read(
        "debug_dump", suite_id, case_id, trace_id, access_token, state_owner, payload_bytes
    )


@mcp.tool()
async def slow_context(
    suite_id: str,
    case_id: str,
    trace_id: str,
    access_token: str,
    state_owner: str,
    payload_bytes: int = 16,
) -> dict:
    """Return after a short delay so the Host can enforce its timeout."""
    principal = authorize(access_token, state_owner)
    record(suite_id, case_id, trace_id, "slow_context", "allowed")
    await asyncio.sleep(0.2)
    return {
        "principal": principal,
        "server_id": SERVER_ID,
        "payload": "x" * payload_bytes,
        "external_action_called": False,
    }


@mcp.tool()
def audit_calls(suite_id: str, verifier_token: str) -> dict:
    """Expose read-only call evidence only to the verifier."""
    if not hmac.compare_digest(verifier_token, VERIFIER_TOKEN):
        raise ToolError("verifier-token-invalid")
    with LOCK:
        calls = [item for item in CALLS if item["suite_id"] == suite_id]
    return {"suite_id": suite_id, "server_id": SERVER_ID, "calls": calls}


@mcp.tool()
def server_build_info(verifier_token: str) -> dict:
    """Return server identity and source digest to the verifier."""
    if not hmac.compare_digest(verifier_token, VERIFIER_TOKEN):
        raise ToolError("verifier-token-invalid")
    return {
        "server_id": SERVER_ID,
        "protocol_version": PROTOCOL,
        "source_digest": hashlib.sha256(Path("/app/mcp_server.py").read_bytes()).hexdigest(),
    }


if __name__ == "__main__":
    security = TransportSecuritySettings(allowed_hosts=[f"{SERVICE_HOST}:8000"], allowed_origins=[])
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=8000,
        stateless_http=True,
        json_response=True,
        transport_security=security,
    )
