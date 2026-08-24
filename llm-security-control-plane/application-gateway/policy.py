"""Application-owned authentication, authorization, and RAG selection policy."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Dict, Optional

import yaml

from auth import AuthError, AuthService


_runtime_policy = Path("/app/policies/application-policy.yaml")
_source_policy = Path(__file__).resolve().parents[1] / "policies/application-policy.yaml"
POLICY_PATH = os.getenv(
    "APPLICATION_POLICY_PATH",
    str(_runtime_policy if _runtime_policy.exists() else _source_policy),
)
with open(POLICY_PATH, encoding="utf-8") as handle:
    POLICY = yaml.safe_load(handle)


class AuthenticationError(ValueError):
    pass


class AuthorizationError(PermissionError):
    pass


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str]
    allowed_classifications: frozenset[str]
    allowed_purposes: frozenset[str]


PRINCIPALS = {
    "hub-public-reader-token": Principal(
        subject="public-reader",
        roles=frozenset({"public_reader"}),
        allowed_classifications=frozenset({"public"}),
        allowed_purposes=frozenset({"public_information"}),
    ),
    "hub-internal-analyst-token": Principal(
        subject="internal-analyst",
        roles=frozenset({"internal_analyst"}),
        allowed_classifications=frozenset({"public", "internal"}),
        allowed_purposes=frozenset({"public_information", "incident_response"}),
    ),
    "hub-support-agent-token": Principal(
        subject="support-agent",
        roles=frozenset({"support_agent"}),
        allowed_classifications=frozenset({"public", "internal", "restricted"}),
        allowed_purposes=frozenset({"public_information", "incident_response", "customer_support"}),
    ),
}


RAG_STORES = {
    "public": {
        "purpose": "public_information",
        "exact_value_required": True,
        "allowed_source_suffixes": ["/public-support.md"],
    },
    "internal": {
        "purpose": "incident_response",
        "exact_value_required": False,
        "allowed_source_suffixes": ["/restricted-incident.md"],
    },
    "restricted": {
        "purpose": "customer_support",
        "exact_value_required": True,
        "allowed_source_suffixes": ["/restricted-incident.md"],
    },
}


def authenticate(
    authorization: Optional[str],
    auth_service: AuthService,
    legacy_static_tokens: bool = False,
) -> Principal:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise AuthenticationError("valid application bearer token required")
    if legacy_static_tokens and token in PRINCIPALS:
        return PRINCIPALS[token]
    try:
        claims = auth_service.verify_access(token)
    except AuthError as exc:
        raise AuthenticationError(str(exc)) from exc
    return Principal(
        subject=str(claims["sub"]),
        roles=frozenset(str(value) for value in claims["roles"]),
        allowed_classifications=frozenset(
            str(value) for value in claims.get("allowed_classifications", [])
        ),
        allowed_purposes=frozenset(
            str(value) for value in claims.get("allowed_purposes", [])
        ),
    )


def authorize_retrieval(
    principal: Principal, classification: str, purpose: str
) -> Optional[Dict]:
    if classification == "none":
        return None
    classification_policy = POLICY["classifications"].get(classification)
    if not classification_policy or not set(principal.roles) & set(classification_policy["required_roles"]):
        raise AuthorizationError("classification-not-authorized")
    if purpose not in classification_policy["allowed_purposes"]:
        raise AuthorizationError("purpose-not-authorized")
    store = RAG_STORES[classification]
    if purpose != store["purpose"]:
        raise AuthorizationError("purpose-does-not-match-rag-store")
    return {
        "classification": classification,
        "purpose": purpose,
        "allowed_source_suffixes": list(store["allowed_source_suffixes"]),
        "exact_value_required": bool(store["exact_value_required"]),
        "authorized_by": "application-policy",
    }


def public_policy() -> dict:
    return {
        "policy_id": POLICY["policy_id"],
        "authentication_source": "application-rs256-jwt",
        "classifications": list(POLICY["classifications"]),
        "prohibited_policy": "not-stored-and-never-sent-to-model",
        "rag_stores": {
            key: {
                "purpose": value["purpose"],
                "exact_value_required": value["exact_value_required"],
                "allowed_source_suffixes": list(value["allowed_source_suffixes"]),
            }
            for key, value in RAG_STORES.items()
        },
    }
