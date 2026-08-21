import os

import httpx
from nemoguardrails import LLMRails
from nemoguardrails.actions import action
from nemoguardrails.actions.actions import ActionResult


PRESIDIO_URL = os.getenv("PRESIDIO_URL", "http://10.0.2.2:18091").rstrip("/")


@action(is_system_action=True)
async def mask_retrieval_with_presidio(text: str, context: dict) -> ActionResult:
    """Detect PII, then apply the Application-selected handling policy."""

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{PRESIDIO_URL}/api/scan",
            json={"text": text},
        )
        response.raise_for_status()
        payload = response.json()
    sanitized = payload.get("sanitized_text")
    if not isinstance(sanitized, str):
        raise ValueError("Presidio returned an invalid sanitized_text contract")
    entity_types = payload.get("entity_types", [])
    if not isinstance(entity_types, list) or not all(
        isinstance(item, str) for item in entity_types
    ):
        raise ValueError("Presidio returned an invalid entity_types contract")

    handling_policy = context.get("retrieval_handling_policy", "redact")
    if handling_policy == "allow-exact-after-application-authorization":
        output = text
        application_decision = "allow_unredacted"
    elif handling_policy == "redact":
        output = sanitized
        application_decision = "redact" if sanitized != text else "allow"
    else:
        raise ValueError("unsupported retrieval handling policy")

    return ActionResult(
        return_value=output,
        context_updates={
            "retrieval_pii_detected": bool(entity_types),
            "retrieval_entity_types": sorted(set(entity_types)),
            "retrieval_redaction_applied": output != text,
            "retrieval_application_decision": application_decision,
        },
    )


@action(is_system_action=True)
async def retrieve_lab_chunks(context: dict) -> ActionResult:
    """Expose request-scoped lab chunks through NeMo's retrieval action hook."""

    chunks = context.get("lab_retrieval_chunks", "")
    if not isinstance(chunks, str):
        raise ValueError("lab_retrieval_chunks must be a string")
    return ActionResult(
        return_value=chunks,
        context_updates={"relevant_chunks": chunks},
    )


def init(app: LLMRails) -> None:
    app.register_action(
        mask_retrieval_with_presidio,
        "mask_retrieval_with_presidio",
    )
    app.register_action(retrieve_lab_chunks, "retrieve_relevant_chunks")
