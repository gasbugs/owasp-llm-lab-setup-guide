#!/usr/bin/env python3
"""Deterministic LLM security policy evaluation and telemetry sanitization."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ALLOWED_STAGES = {"input", "retrieval", "tool", "output", "guardrail", "runtime"}
ALLOWED_DECISIONS = {"allow", "observe", "redact", "block", "infra"}

DEFAULT_SENSITIVE_PATTERNS = {
    "DEMO_API_KEY": r"\bDEMO_API_KEY=[A-Za-z0-9-]+\b",
    "EMAIL_ADDRESS": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "KR_RRN": r"\b\d{6}-[1-4]\d{6}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "PHONE_NUMBER": r"(?<!\d)(?:\+?\d{1,3}[ -]?)?(?:\d{2,3}[ -]?)?\d{3,4}[ -]?\d{4}(?!\d)",
}


class PolicyError(ValueError):
    pass


def load_policy(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    required = {
        "version",
        "mode",
        "prompt_injection",
        "sensitive_data",
        "rag_tenant_boundary",
        "agent_approval",
        "request_limit",
    }
    missing = sorted(required - set(data))
    if missing:
        raise PolicyError(f"policy fields missing: {', '.join(missing)}")
    if data["mode"] not in {"audit", "enforce"}:
        raise PolicyError("policy mode must be audit or enforce")
    threshold = data["prompt_injection"].get("risk_threshold")
    if not isinstance(threshold, (int, float)) or not 0 <= threshold <= 1:
        raise PolicyError("prompt injection threshold must be between 0 and 1")
    patterns = data["sensitive_data"].get("patterns", {})
    if not isinstance(patterns, dict) or not all(
        isinstance(name, str) and isinstance(pattern, str)
        for name, pattern in patterns.items()
    ):
        raise PolicyError("sensitive_data.patterns must map entity names to regex strings")
    try:
        for pattern in patterns.values():
            re.compile(pattern)
    except re.error as exc:
        raise PolicyError(f"invalid sensitive data regex: {exc}") from exc
    return data


def sanitize_text(
    text: str,
    patterns: dict[str, str] | None = None,
) -> tuple[str, list[str]]:
    sanitized = text
    entities: list[str] = []
    configured = DEFAULT_SENSITIVE_PATTERNS if patterns is None else patterns
    for entity, expression in configured.items():
        pattern = re.compile(expression)
        if pattern.search(sanitized):
            entities.append(entity)
            sanitized = pattern.sub(f"<{entity}>", sanitized)
    return sanitized, sorted(set(entities))


def text_identity(
    text: str,
    hmac_key: str,
    patterns: dict[str, str] | None = None,
) -> tuple[str, str, list[str]]:
    sanitized, entities = sanitize_text(text, patterns)
    digest = hmac.new(
        hmac_key.encode("utf-8"),
        text.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    excerpt = sanitized.replace("\r", " ").replace("\n", " ")[:160]
    return digest, excerpt, entities


@dataclass(frozen=True)
class Decision:
    application_decision: str
    policy_rule: str
    severity: str
    reason: str


def _enforced(policy: dict[str, Any], decision: str) -> str:
    if policy["mode"] == "audit" and decision in {"block", "redact"}:
        return "observe"
    return decision


def evaluate(event: dict[str, Any], policy: dict[str, Any]) -> Decision:
    stage = str(event.get("stage", "")).strip().lower()
    if stage not in ALLOWED_STAGES:
        raise PolicyError(f"unsupported stage: {stage or '<empty>'}")

    text = str(event.get("text", ""))
    _sanitized, inferred_entities = sanitize_text(
        text, policy["sensitive_data"].get("patterns")
    )
    entities = sorted(
        set(inferred_entities)
        | {str(item).upper() for item in event.get("detected_entities", [])}
    )
    sensitive_entities = {
        str(item).upper() for item in policy["sensitive_data"].get("entities", [])
    }
    if (
        policy["sensitive_data"].get("enabled", True)
        and sensitive_entities.intersection(entities)
    ):
        decision = _enforced(policy, policy["sensitive_data"].get("action", "redact"))
        return Decision(decision, "sensitive-data", "high", "sensitive entity detected")

    if stage == "retrieval" and policy["rag_tenant_boundary"].get("enabled", True):
        authenticated = event.get("authenticated_tenant")
        resource = event.get("resource_tenant")
        if authenticated and resource and authenticated != resource:
            decision = _enforced(policy, policy["rag_tenant_boundary"].get("action", "block"))
            return Decision(decision, "rag-tenant-boundary", "critical", "retrieval tenant mismatch")

    if stage == "tool" and policy["agent_approval"].get("enabled", True):
        dangerous = set(policy["agent_approval"].get("dangerous_tools", []))
        if event.get("tool_name") in dangerous and event.get("approval_status") != "approved":
            decision = _enforced(policy, policy["agent_approval"].get("action", "block"))
            return Decision(decision, "agent-execution-approval", "critical", "dangerous tool lacks approval")

    if stage == "runtime" and policy["request_limit"].get("enabled", True):
        count = int(event.get("window_request_count", 0))
        limit = int(policy["request_limit"].get("max_requests_per_window", 5))
        if count > limit:
            decision = _enforced(policy, policy["request_limit"].get("action", "block"))
            return Decision(decision, "request-rate-limit", "high", f"request count {count} exceeds {limit}")

    if stage == "input" and policy["prompt_injection"].get("enabled", True):
        event_type = str(event.get("event_type", ""))
        exempt = set(policy["prompt_injection"].get("benign_event_types", []))
        risk_score = float(event.get("risk_score", 0.0))
        threshold = float(policy["prompt_injection"]["risk_threshold"])
        if event_type not in exempt and risk_score >= threshold:
            decision = _enforced(policy, policy["prompt_injection"].get("action", "block"))
            return Decision(decision, "prompt-injection-risk", "high", f"risk score {risk_score:.2f} meets {threshold:.2f}")

    return Decision("allow", "default-allow", "info", "no policy rule matched")


def normalize_observed_decision(value: object) -> str:
    decision = str(value or "observe").strip().lower()
    aliases = {"deny": "block", "blocked": "block", "sanitized": "redact"}
    decision = aliases.get(decision, decision)
    return decision if decision in ALLOWED_DECISIONS else "observe"
