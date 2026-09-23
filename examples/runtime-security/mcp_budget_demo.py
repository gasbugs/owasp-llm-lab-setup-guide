"""MCP Tool call, result-byte, and state-owner budget demonstration."""

from __future__ import annotations

import asyncio
import json
import secrets

from mcp import Client
from mcp.server import MCPServer


PROTOCOL = "2026-07-28"
MAX_TOOL_CALLS = 2
MAX_RESULT_BYTES = 96
SERVER_CALLS: list[dict] = []
mcp = MCPServer("runtime-budget-tools")


@mcp.tool()
def read_context(trace_id: str, owner: str, payload_bytes: int) -> dict:
    """Return a deterministic Tool result and record its trace."""
    SERVER_CALLS.append({"trace_id": trace_id, "owner": owner, "payload_bytes": payload_bytes})
    return {"trace_id": trace_id, "owner": owner, "payload": "x" * payload_bytes}


@mcp.tool()
async def slow_context(trace_id: str, owner: str) -> dict:
    """Delay longer than the Host budget without performing an external action."""
    SERVER_CALLS.append({"trace_id": trace_id, "owner": owner, "tool": "slow_context"})
    await asyncio.sleep(0.2)
    return {"trace_id": trace_id, "owner": owner, "payload": "late"}


def payload(result) -> dict:
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


async def main() -> None:
    principal = "team-a"
    trace_id = secrets.token_hex(16)
    async with Client(mcp, mode=PROTOCOL) as client:
        normal = await client.call_tool(
            "read_context", {"trace_id": trace_id, "owner": principal, "payload_bytes": 8}
        )
        loop_calls = 0
        for _ in range(MAX_TOOL_CALLS):
            await client.call_tool(
                "read_context", {"trace_id": trace_id, "owner": principal, "payload_bytes": 8}
            )
            loop_calls += 1
        loop_blocked = loop_calls == MAX_TOOL_CALLS
        oversized = await client.call_tool(
            "read_context", {"trace_id": trace_id, "owner": principal, "payload_bytes": 128}
        )
        oversized_bytes = len(json.dumps(payload(oversized), separators=(",", ":")).encode())
        oversized_forwarded = oversized_bytes <= MAX_RESULT_BYTES
        try:
            await asyncio.wait_for(
                client.call_tool("slow_context", {"trace_id": trace_id, "owner": principal}),
                timeout=0.05,
            )
            timeout_blocked = False
        except TimeoutError:
            timeout_blocked = True
        foreign_owner = "team-b"
        foreign_called = False
        if foreign_owner == principal:
            await client.call_tool(
                "read_context", {"trace_id": trace_id, "owner": foreign_owner, "payload_bytes": 8}
            )
            foreign_called = True
        print(json.dumps({
            "protocol_version": client.protocol_version,
            "trace_id": trace_id,
            "normal": {"is_error": bool(normal.is_error), "context_forwarded": True},
            "tool_loop": {"requested": 3, "executed": loop_calls, "third_call_blocked": loop_blocked},
            "oversized_result": {"result_bytes": oversized_bytes, "limit": MAX_RESULT_BYTES, "context_forwarded": oversized_forwarded},
            "tool_timeout": {"limit_ms": 50, "blocked": timeout_blocked, "retried": False},
            "foreign_state": {"owner": foreign_owner, "tool_called": foreign_called, "reason": "state-owner-mismatch"},
            "server_calls": SERVER_CALLS,
        }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
