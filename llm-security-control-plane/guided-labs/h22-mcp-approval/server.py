"""Learner-owned MCP server for exact-call approval and one-time effects."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings


APPROVAL_SECRET = os.environ["GUIDED_H22_APPROVAL_SECRET"].encode()
DATABASE_PATH = os.getenv("GUIDED_H22_DATABASE", "/state/h22.sqlite3")
SOURCE_PATH = Path("/app/server.py")
SERVER_ID = "training-notice-mcp"
PROTOCOL_VERSION = "2026-07-28"

Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        "CREATE TABLE IF NOT EXISTS consumed (nonce TEXT PRIMARY KEY, suite_id TEXT NOT NULL)"
    )
    database.execute(
        "CREATE TABLE IF NOT EXISTS effects "
        "(effect_id INTEGER PRIMARY KEY AUTOINCREMENT, call_id TEXT NOT NULL, "
        "suite_id TEXT NOT NULL, notice TEXT NOT NULL, trace_id TEXT NOT NULL)"
    )


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


def decode_token(token: str) -> dict:
    encoded, separator, signature = token.partition(".")
    if not separator:
        raise ToolError("approval-token-missing")
    expected = hmac.new(APPROVAL_SECRET, encoded.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ToolError("approval-signature-invalid")
    padding = "=" * (-len(encoded) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded + padding))


def verify_approval(
    approval_token: str,
    suite_id: str,
    call_id: str,
    trace_id: str,
    requester: str,
    notice: str,
) -> str:
    claims = decode_token(approval_token)
    expected = {
        "suite_id": suite_id,
        "requester": requester,
        "reviewer": "course-reviewer",
        "server_id": SERVER_ID,
        "tool": "publish_notice",
        "args_sha256": canonical_digest(suite_id, call_id, trace_id, requester, notice),
    }
    if any(claims.get(key) != value for key, value in expected.items()):
        raise ToolError("approval-exact-call-mismatch")
    if int(claims.get("expires_at", 0)) <= int(time.time()):
        raise ToolError("approval-expired")
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise ToolError("approval-nonce-invalid")
    return nonce


mcp = MCPServer(
    SERVER_ID,
    instructions="Training-only notice tools. Host approval is not model authority.",
)


@mcp.tool()
def lookup_notice(suite_id: str) -> dict:
    """Read the training notice count for one isolated suite."""
    with connect() as database:
        count = database.execute(
            "SELECT COUNT(*) FROM effects WHERE suite_id=?", (suite_id,)
        ).fetchone()[0]
    return {"suite_id": suite_id, "effects": count, "external_action_called": False}


@mcp.tool()
def publish_notice(
    suite_id: str,
    call_id: str,
    trace_id: str,
    requester: str,
    notice: str,
    approval_token: str = "",
) -> dict:
    """Publish one local training notice after an exact-call approval."""
    # TODO(H22): 모델의 Tool 제안을 권한으로 믿지 말고 exact-call 승인을 검사한다.
    nonce = secrets.token_hex(16)

    try:
        with connect() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "INSERT INTO consumed VALUES(?,?)", (nonce, suite_id)
            )
            database.execute(
                "INSERT INTO effects(call_id,suite_id,notice,trace_id) VALUES(?,?,?,?)",
                (call_id, suite_id, notice, trace_id),
            )
            effects = database.execute(
                "SELECT COUNT(*) FROM effects WHERE suite_id=?", (suite_id,)
            ).fetchone()[0]
    except sqlite3.IntegrityError as exc:
        raise ToolError("approval-already-consumed") from exc
    return {
        "decision": "allow",
        "suite_id": suite_id,
        "call_id": call_id,
        "trace_id": trace_id,
        "effects": effects,
        "external_action_called": False,
    }


@mcp.tool()
def audit_effects(suite_id: str) -> dict:
    """Return read-only effect evidence for the independent verifier."""
    with connect() as database:
        rows = database.execute(
            "SELECT call_id, trace_id, notice FROM effects WHERE suite_id=? ORDER BY rowid", (suite_id,)
        ).fetchall()
    return {
        "suite_id": suite_id,
        "effects": len(rows),
        "calls": [dict(row) for row in rows],
        "external_action_called": False,
    }


@mcp.tool()
def server_build_info() -> dict:
    """Return the server identity and source digest without changing state."""
    return {
        "server_id": SERVER_ID,
        "protocol_version": PROTOCOL_VERSION,
        "source_digest": hashlib.sha256(SOURCE_PATH.read_bytes()).hexdigest(),
    }


if __name__ == "__main__":
    security = TransportSecuritySettings(
        allowed_hosts=["guided-h22-mcp-server:8000"], allowed_origins=[]
    )
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=8000,
        stateless_http=True,
        json_response=True,
        transport_security=security,
    )
