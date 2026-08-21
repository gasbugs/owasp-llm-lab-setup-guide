"""Application-owned policy for the classified RAG training endpoint.

Presidio detects personal data and NeMo runs the retrieval rail, but neither
component decides which corpus a caller may read.  This module keeps that
authorization decision in ordinary server code and returns only synthetic lab
documents that the authenticated principal may use.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


Classification = Literal["public", "restricted"]


class RagAuthenticationError(ValueError):
    """Raised when the application cannot bind a request to a principal."""


class RagAuthorizationError(PermissionError):
    """Raised before retrieval when a principal cannot use a classification."""


@dataclass(frozen=True)
class RagPrincipal:
    subject: str
    allowed_classifications: frozenset[Classification]


@dataclass(frozen=True)
class RagDocument:
    document_id: str
    classification: Classification
    text: str
    exact_value_required: bool


# Synthetic lab credentials.  Production code would validate an IdP-issued
# token and derive roles/claims from that trusted identity instead.
PRINCIPALS = {
    "rag-public-reader-token": RagPrincipal(
        subject="public-reader",
        allowed_classifications=frozenset({"public"}),
    ),
    "rag-support-agent-token": RagPrincipal(
        subject="support-agent",
        allowed_classifications=frozenset({"public", "restricted"}),
    ),
}


# The stores are physically represented as separate immutable collections in
# this lab.  A real service can map them to separate indexes, databases, or
# namespaces with independent IAM and encryption policies.
RAG_STORES: dict[Classification, tuple[RagDocument, ...]] = {
    "public": (
        RagDocument(
            document_id="public/security-contact.md",
            classification="public",
            text="Public security contact: security@example.com.",
            exact_value_required=True,
        ),
    ),
    "restricted": (
        RagDocument(
            document_id="restricted/customer-recovery.md",
            classification="restricted",
            text="Synthetic customer recovery contact: customer.demo@example.com.",
            exact_value_required=True,
        ),
    ),
}


def authenticate(authorization: str | None) -> RagPrincipal:
    """Authenticate from a server-side token map, never request-body identity."""

    scheme, _, token = (authorization or "").partition(" ")
    principal = PRINCIPALS.get(token) if scheme.lower() == "bearer" else None
    if principal is None:
        raise RagAuthenticationError("valid classified RAG bearer token required")
    return principal


def retrieve_authorized(
    *,
    principal: RagPrincipal,
    classification: Classification,
) -> dict:
    """Authorize first, then select one already-classified RAG store."""

    if classification not in principal.allowed_classifications:
        raise RagAuthorizationError("classification-not-authorized")

    documents = RAG_STORES[classification]
    return {
        "authenticated_subject": principal.subject,
        "requested_classification": classification,
        "selected_rag": f"{classification}-rag",
        "handling_policy": "allow-exact-after-application-authorization",
        "documents": [
            {
                "document_id": document.document_id,
                "classification": document.classification,
                "text": document.text,
                "exact_value_required": document.exact_value_required,
            }
            for document in documents
        ],
    }
