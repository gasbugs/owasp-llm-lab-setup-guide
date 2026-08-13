"""NodeGoat-style vulnerable/safe policy pairs used by learner workshops."""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass
from typing import Literal

from fastapi import HTTPException, Request

from app.scenarios import day2 as day2_scenario


@dataclass(frozen=True)
class PolicyDecision:
    lab: str
    policy: str
    application_decision: Literal["allow", "block"]
    blocking_reason: str | None = None
    max_output_tokens: int | None = None


@dataclass(frozen=True)
class CustomerBinding:
    customer_id: str
    mode: Literal["vulnerable", "safe"]
    principal: day2_scenario.LLM02Principal | None


def emit_security_event(decision: PolicyDecision, *, upstream_called: bool) -> None:
    event = {
        "event": "secure_coding_policy",
        **asdict(decision),
        "upstream_called": upstream_called,
        "timestamp_ms": int(time.time() * 1000),
    }
    print(json.dumps(event, ensure_ascii=False), flush=True)


def allow_untrusted_llm01_input(_: str) -> PolicyDecision:
    return PolicyDecision("llm01", "accept-untrusted-input", "allow")


def enforce_llm01_input_policy(message: str) -> PolicyDecision:
    injection = re.compile(
        r"ignore\s+(all\s+)?previous|system\s+prompt|secret[_ -]?flag|"
        r"이전\s*지시.*무시|시스템\s*프롬프트|비밀\s*값",
        re.IGNORECASE,
    )
    if injection.search(message):
        return PolicyDecision(
            "llm01",
            "server-input-policy",
            "block",
            "prompt-injection-pattern",
        )
    return PolicyDecision("llm01", "server-input-policy", "allow")


def trust_llm02_request_body(request_body: object, _: Request) -> CustomerBinding:
    customer_id = getattr(request_body, "customer_id", None) or day2_scenario.LLM02_CUSTOMER_ID
    return CustomerBinding(customer_id, "vulnerable", None)


def authenticate_llm02_bearer(request_body: object, request: Request) -> CustomerBinding:
    if getattr(request_body, "customer_id", None) is not None:
        raise HTTPException(status_code=422, detail="customer_id must not be supplied by client")
    try:
        principal = day2_scenario.authenticate_customer(
            request.headers.get("authorization")
        )
    except day2_scenario.LLM02AuthenticationError as exc:
        raise HTTPException(
            status_code=401,
            detail="valid LLM02 lab bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    return CustomerBinding(principal.customer_id, "safe", principal)


def include_unapproved_documents() -> Literal["vulnerable", "safe"]:
    return "vulnerable"


def require_approved_documents() -> Literal["vulnerable", "safe"]:
    return "safe"


def search_all_tenants() -> Literal["vulnerable", "safe"]:
    return "vulnerable"


def filter_authenticated_tenant() -> Literal["vulnerable", "safe"]:
    return "safe"


def trust_llm09_model_recommendation(candidate: str) -> PolicyDecision:
    del candidate
    return PolicyDecision("llm09", "model-recommendation-only", "allow")


def require_llm09_approved_package(candidate: str) -> PolicyDecision:
    approved_packages = {"pyfiglet", "rich", "terminaltables"}
    if candidate.strip().lower() not in approved_packages:
        return PolicyDecision(
            "llm09",
            "server-approved-package-allowlist",
            "block",
            "package-not-approved",
        )
    return PolicyDecision(
        "llm09", "server-approved-package-allowlist", "allow"
    )


def allow_unbounded_generation(message: str) -> PolicyDecision:
    del message
    return PolicyDecision("llm10", "unbounded-request-and-output", "allow")


def enforce_llm10_resource_budget(message: str) -> PolicyDecision:
    if len(message) > 1200:
        return PolicyDecision(
            "llm10",
            "server-resource-budget",
            "block",
            "input-character-limit-1200",
            128,
        )
    return PolicyDecision(
        "llm10", "server-resource-budget", "allow", max_output_tokens=128
    )
