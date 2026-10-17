"""Learner-owned Agent Gateway admission policy for H21."""

from __future__ import annotations

from dataclasses import dataclass


class PolicyDenied(ValueError):
    """Stop before the model provider or MCP server is contacted."""


@dataclass(frozen=True)
class Admission:
    principal: str
    model: str
    server_id: str
    tool: str
    max_tool_calls: int
    max_result_bytes: int
    tool_timeout_ms: int


POLICIES = {
    "support-agent": {
        "models": {"us.amazon.nova-lite-v1:0"},
        "servers": {"training-notice-mcp"},
        "tools": {"lookup_notice", "oversized_context", "slow_context"},
        "max_tool_calls": 2,
        "max_result_bytes": 160,
        "tool_timeout_ms": 250,
    }
}


def authorize(
    principal: str,
    model: str,
    server_id: str,
    tool: str,
    requested_tool_calls: int,
    requested_result_bytes: int,
    requested_timeout_ms: int,
    state_owner: str,
) -> Admission:
    """Return server-owned limits after validating every Agent boundary."""
    configured = POLICIES.get(principal)
    # TODO 1: 설정이 없는 principal은 PolicyDenied로 호출 전에 거부하세요.
    # TODO 2: model·server·tool 허용 목록과 state_owner를 검사하세요.
    # TODO 3: 요청한 Tool 횟수·결과 bytes·timeout이 정책 상한을 넘으면 거부하세요.
    # TODO 4: 허용되면 요청값 대신 configured의 상한으로 Admission을 만드세요.
    return Admission(
        principal=principal,
        model=model,
        server_id=server_id,
        tool=tool,
        max_tool_calls=requested_tool_calls,
        max_result_bytes=requested_result_bytes,
        tool_timeout_ms=requested_timeout_ms,
    )
