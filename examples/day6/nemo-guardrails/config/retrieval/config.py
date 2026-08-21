import os

import httpx
from nemoguardrails import LLMRails
from nemoguardrails.actions import action
from nemoguardrails.actions.actions import ActionResult


PRESIDIO_URL = os.getenv("PRESIDIO_URL", "http://10.0.2.2:18091").rstrip("/")


@action(is_system_action=True)
async def mask_retrieval_with_presidio(text: str) -> str:
    """Delegate PII detection to Presidio before a RAG chunk reaches the LLM."""

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
    return sanitized


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
