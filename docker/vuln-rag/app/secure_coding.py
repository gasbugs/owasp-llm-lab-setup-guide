"""NodeGoat-style vulnerable/safe policy pairs used by learner workshops."""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass
from typing import Literal, Protocol

from fastapi import HTTPException, Request

from app.scenarios import day2 as day2_scenario


@dataclass(frozen=True)
class PolicyDecision:
    lab: str
    policy: str
    application_decision: Literal["allow", "block"]
    blocking_reason: str | None = None
    max_output_tokens: int | None = None


class CustomerToolRequest(Protocol):
    customer_id: str | None
    fields: list[str]
    reason: str


@dataclass(frozen=True)
class CustomerToolResult:
    mode: Literal["vulnerable", "safe"]
    customer_id: str
    fields: tuple[str, ...]
    record: dict[str, str]


class LLM02AuthorizationError(ValueError):
    """Raised before a customer query when tool scope is not authorized."""


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
        r"ignore\s+(all\s+)?previous|system\s+prompt|"
        r"secret(?:[_ -]?flag|\s+(?:or|또는)\s+flag)|"
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


def select_llm01_input_policy(message: str) -> PolicyDecision:
    # NODEGOAT-LAB: LLM01 — switch the input-policy call here.
    return allow_untrusted_llm01_input(message)  # VULNERABLE-ACTIVE
    # return enforce_llm01_input_policy(message)  # SAFE-ENABLE


def require_llm02_authenticated_principal(
    request_body: object,
    request: Request,
) -> day2_scenario.LLM02Principal:
    del request_body
    try:
        return day2_scenario.authenticate_customer(
            request.headers.get("authorization")
        )
    except day2_scenario.LLM02AuthenticationError as exc:
        raise HTTPException(
            status_code=401,
            detail="valid LLM02 lab bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def execute_customer_tool_vulnerable(
    tool_request: CustomerToolRequest,
    principal: day2_scenario.LLM02Principal,
) -> CustomerToolResult:
    requested_customer_id = tool_request.customer_id
    requested_fields = tuple(tool_request.fields)
    target = requested_customer_id or principal.customer_id
    return CustomerToolResult(
        mode="vulnerable",
        customer_id=target,
        fields=requested_fields,
        record=day2_scenario.get_customer_record(target, requested_fields),
    )


def execute_customer_tool_safe(
    tool_request: CustomerToolRequest,
    principal: day2_scenario.LLM02Principal,
) -> CustomerToolResult:
    requested_customer_id = tool_request.customer_id
    requested_fields = set(tool_request.fields)
    target = requested_customer_id or principal.customer_id

    if target != principal.customer_id:
        raise LLM02AuthorizationError("customer-scope-denied")

    allowed_fields = {
        "customer_id",
        "delivery_status",
        "estimated_arrival",
    }
    if requested_fields - allowed_fields:
        raise LLM02AuthorizationError("field-not-allowed")

    ordered_fields = tuple(tool_request.fields)
    return CustomerToolResult(
        mode="safe",
        customer_id=principal.customer_id,
        fields=ordered_fields,
        record=day2_scenario.get_customer_record(
            principal.customer_id,
            ordered_fields,
        ),
    )


def select_llm02_tool_executor(
    tool_request: CustomerToolRequest,
    principal: day2_scenario.LLM02Principal,
) -> CustomerToolResult:
    # NODEGOAT-LAB: LLM02 — switch authorization of the LLM-proposed tool call here.
    return execute_customer_tool_vulnerable(tool_request, principal)  # VULNERABLE-ACTIVE
    # return execute_customer_tool_safe(tool_request, principal)  # SAFE-ENABLE


def include_unapproved_documents() -> Literal["vulnerable", "safe"]:
    return "vulnerable"


def require_approved_documents() -> Literal["vulnerable", "safe"]:
    return "safe"


def select_llm04_provenance_filter() -> Literal["vulnerable", "safe"]:
    # NODEGOAT-LAB: LLM04 — switch provenance filtering here.
    return include_unapproved_documents()  # VULNERABLE-ACTIVE
    # return require_approved_documents()  # SAFE-ENABLE


def search_all_tenants() -> Literal["vulnerable", "safe"]:
    return "vulnerable"


def filter_authenticated_tenant() -> Literal["vulnerable", "safe"]:
    return "safe"


def select_llm08_tenant_filter() -> Literal["vulnerable", "safe"]:
    # NODEGOAT-LAB: LLM08 — switch the pre-ranking tenant boundary here.
    return search_all_tenants()  # VULNERABLE-ACTIVE
    # return filter_authenticated_tenant()  # SAFE-ENABLE


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


def select_llm09_package_policy(candidate: str) -> PolicyDecision:
    # NODEGOAT-LAB: LLM09 — switch the package-install trust boundary here.
    return trust_llm09_model_recommendation(candidate)  # VULNERABLE-ACTIVE
    # return require_llm09_approved_package(candidate)  # SAFE-ENABLE


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


def select_llm10_resource_budget(message: str) -> PolicyDecision:
    # NODEGOAT-LAB: LLM10 — switch request and output budgets here.
    return allow_unbounded_generation(message)  # VULNERABLE-ACTIVE
    # return enforce_llm10_resource_budget(message)  # SAFE-ENABLE
