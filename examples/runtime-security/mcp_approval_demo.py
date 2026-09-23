"""Instructor-led MCP exact-call approval demonstration with local effects only."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import time

from mcp import Client
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError


PROTOCOL = "2026-07-28"
SERVER_ID = "runtime-training-notice"
SECRET = secrets.token_bytes(32)
EFFECTS: list[str] = []
CONSUMED: set[str] = set()
mcp = MCPServer(SERVER_ID)


def digest(notice: str) -> str:
    raw = json.dumps({"notice": notice}, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def approve(requester: str, reviewer: str, notice: str) -> str:
    if requester == reviewer:
        raise ValueError("self-approval-denied")
    claims = {
        "requester": requester,
        "reviewer": reviewer,
        "server_id": SERVER_ID,
        "tool": "publish_notice",
        "args_sha256": digest(notice),
        "expires_at": int(time.time()) + 300,
        "nonce": secrets.token_hex(16),
    }
    encoded = base64.urlsafe_b64encode(json.dumps(claims, sort_keys=True).encode()).decode()
    return encoded + "." + hmac.new(SECRET, encoded.encode(), hashlib.sha256).hexdigest()


def verify(token: str, requester: str, notice: str) -> str:
    encoded, separator, signature = token.partition(".")
    expected = hmac.new(SECRET, encoded.encode(), hashlib.sha256).hexdigest()
    if not separator or not hmac.compare_digest(signature, expected):
        raise ToolError("approval-invalid")
    claims = json.loads(base64.urlsafe_b64decode(encoded))
    exact = (
        claims.get("requester") == requester
        and claims.get("reviewer") == "reviewer"
        and claims.get("server_id") == SERVER_ID
        and claims.get("tool") == "publish_notice"
        and claims.get("args_sha256") == digest(notice)
        and claims.get("expires_at", 0) > int(time.time())
    )
    if not exact or claims.get("nonce") in CONSUMED:
        raise ToolError("approval-mismatch-expired-or-consumed")
    return claims["nonce"]


@mcp.tool()
def lookup_notice() -> dict:
    """Read the local training effect count."""
    return {"effects": len(EFFECTS), "external_action_called": False}


@mcp.tool()
def publish_notice(requester: str, notice: str, approval_token: str = "") -> dict:
    """Create one local notice after exact-call approval."""
    nonce = verify(approval_token, requester, notice)
    CONSUMED.add(nonce)
    EFFECTS.append(notice)
    return {"effects": len(EFFECTS), "external_action_called": False}


def summary(result) -> dict:
    return {"is_error": bool(result.is_error), "effects": len(EFFECTS)}


async def main() -> None:
    requester, reviewer, notice = "requester", "reviewer", "점검 완료"
    async with Client(mcp, mode=PROTOCOL) as client:
        tools = await client.list_tools()
        normal = await client.call_tool("lookup_notice", {})
        missing = await client.call_tool(
            "publish_notice", {"requester": requester, "notice": notice}
        )
        missing_summary = summary(missing)
        token = approve(requester, reviewer, notice)
        changed = await client.call_tool(
            "publish_notice",
            {"requester": requester, "notice": "변경된 공지", "approval_token": token},
        )
        changed_summary = summary(changed)
        allowed = await client.call_tool(
            "publish_notice",
            {"requester": requester, "notice": notice, "approval_token": token},
        )
        allowed_summary = summary(allowed)
        reused = await client.call_tool(
            "publish_notice",
            {"requester": requester, "notice": notice, "approval_token": token},
        )
        reused_summary = summary(reused)
        print(
            json.dumps(
                {
                    "protocol_version": client.protocol_version,
                    "server_id": SERVER_ID,
                    "tools": sorted(tool.name for tool in tools.tools),
                    "normal": {"is_error": bool(normal.is_error), "effects": 0},
                    "no_approval": missing_summary,
                    "changed_args": changed_summary,
                    "approved": allowed_summary,
                    "reuse": reused_summary,
                    "effect_counts": [
                        missing_summary["effects"],
                        changed_summary["effects"],
                        allowed_summary["effects"],
                        reused_summary["effects"],
                    ],
                    "external_action_called": False,
                },
                ensure_ascii=False,
                indent=2,
            )
        )


if __name__ == "__main__":
    asyncio.run(main())
