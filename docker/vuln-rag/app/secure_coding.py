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
    if getattr(request_body, "customer_id", None) is not None:
        raise HTTPException(status_code=422, detail="customer_id must not be supplied by client")
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


def trust_llm02_system_prompt(
    principal: day2_scenario.LLM02Principal,
) -> CustomerBinding:
    return CustomerBinding(principal.customer_id, "vulnerable", principal)


def enforce_llm02_server_data_minimization(
    principal: day2_scenario.LLM02Principal,
) -> CustomerBinding:
    return CustomerBinding(principal.customer_id, "safe", principal)


def select_llm02_disclosure_policy(
    principal: day2_scenario.LLM02Principal,
) -> CustomerBinding:
    # NODEGOAT-LAB: LLM02 — switch disclosure-policy ownership here.
    return trust_llm02_system_prompt(principal)  # VULNERABLE-ACTIVE
    # return enforce_llm02_server_data_minimization(principal)  # SAFE-ENABLE


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
