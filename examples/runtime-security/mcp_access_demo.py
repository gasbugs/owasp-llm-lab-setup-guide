"""MCP server, Tool, and synthetic OAuth audience boundary demonstration."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time

from mcp import Client
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError


PROTOCOL = "2026-07-28"
SERVER_ID = "runtime-training-notice"
SECRET = b"local-training-secret"
CALLS: list[dict] = []
mcp = MCPServer(SERVER_ID)


def issue(subject: str, audience: str) -> str:
    claims = {"issuer": "training-idp", "subject": subject, "audience": audience,
              "scope": "tools:read", "expires_at": int(time.time()) + 300}
    encoded = base64.urlsafe_b64encode(json.dumps(claims, sort_keys=True).encode()).decode()
    return encoded + "." + hmac.new(SECRET, encoded.encode(), hashlib.sha256).hexdigest()


def verify(token: str) -> str:
    encoded, separator, signature = token.partition(".")
    expected = hmac.new(SECRET, encoded.encode(), hashlib.sha256).hexdigest()
    if not separator or not hmac.compare_digest(signature, expected):
        raise ToolError("oauth-token-invalid")
    claims = json.loads(base64.urlsafe_b64decode(encoded))
    if claims.get("issuer") != "training-idp" or claims.get("audience") != SERVER_ID:
        raise ToolError("oauth-resource-or-audience-invalid")
    if "tools:read" not in claims.get("scope", "").split():
        raise ToolError("oauth-scope-missing")
    return claims["subject"]


@mcp.tool()
def lookup_notice(access_token: str) -> dict:
    """Return one local fixture after resource and scope validation."""
    try:
        subject = verify(access_token)
    except ToolError:
        CALLS.append({"tool": "lookup_notice", "outcome": "denied"})
        raise
    CALLS.append({"tool": "lookup_notice", "outcome": "allowed"})
    return {"subject": subject, "notice": "점검 완료", "external_action_called": False}


def admit_server_tool(server_id: str, tool: str) -> None:
    if server_id != SERVER_ID:
        raise ValueError("mcp-server-not-allowed")
    if tool != "lookup_notice":
        raise ValueError("tool-not-allowed")


async def main() -> None:
    async with Client(mcp, mode=PROTOCOL) as client:
        tools = await client.list_tools()
        admit_server_tool(SERVER_ID, "lookup_notice")
        normal = await client.call_tool(
            "lookup_notice", {"access_token": issue("team-a", SERVER_ID)}
        )
        try:
            admit_server_tool("untrusted-server", "lookup_notice")
            untrusted = "allowed"
        except ValueError as exc:
            untrusted = str(exc)
        try:
            admit_server_tool(SERVER_ID, "debug_dump")
            forbidden_tool = "allowed"
        except ValueError as exc:
            forbidden_tool = str(exc)
        wrong_audience = await client.call_tool(
            "lookup_notice", {"access_token": issue("team-a", "another-resource")}
        )
        print(json.dumps({
            "protocol_version": client.protocol_version,
            "server_id": SERVER_ID,
            "tool_inventory": sorted(tool.name for tool in tools.tools),
            "normal": {"is_error": bool(normal.is_error), "downstream_calls": 1},
            "untrusted_server": {"reason": untrusted, "downstream_calls": 0},
            "forbidden_tool": {"reason": forbidden_tool, "downstream_calls": 0},
            "wrong_audience": {"is_error": bool(wrong_audience.is_error), "effect_calls": 0},
            "server_audit": CALLS,
        }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
