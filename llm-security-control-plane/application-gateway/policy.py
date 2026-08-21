"""Application-owned authentication, authorization, and RAG selection policy."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

import yaml


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
        "chunks": ["Public security contact: security@example.com."],
    },
    "internal": {
        "purpose": "incident_response",
        "exact_value_required": False,
        "chunks": ["Internal incident process owner: incident.lead@example.com."],
    },
    "restricted": {
        "purpose": "customer_support",
        "exact_value_required": True,
        "chunks": ["Synthetic customer recovery contact: customer.demo@example.com."],
    },
}


def authenticate(authorization: str | None) -> Principal:
    scheme, _, token = (authorization or "").partition(" ")
    principal = PRINCIPALS.get(token) if scheme.lower() == "bearer" else None
    if principal is None:
        raise AuthenticationError("valid application bearer token required")
    return principal


def authorize_retrieval(principal: Principal, classification: str, purpose: str) -> dict | None:
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
        "chunks": list(store["chunks"]),
        "exact_value_required": bool(store["exact_value_required"]),
        "authorized_by": "application-policy",
    }


def public_policy() -> dict:
    return {
        "policy_id": POLICY["policy_id"],
        "authentication_source": "server-side-bearer-token-map",
        "classifications": list(POLICY["classifications"]),
        "prohibited_policy": "not-stored-and-never-sent-to-model",
        "rag_stores": {
            key: {
                "purpose": value["purpose"],
                "exact_value_required": value["exact_value_required"],
            }
            for key, value in RAG_STORES.items()
        },
    }
