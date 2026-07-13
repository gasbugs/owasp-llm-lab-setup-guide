"""Ollama ``/api/embed`` client used by the LLM08 lab backend."""
from __future__ import annotations

import math
import os
from collections.abc import Sequence

import httpx


class EmbeddingBackendError(RuntimeError):
    """The configured Ollama embedding backend did not return a usable result."""


class EmbeddingClient:
    """Small batch embedding client sharing the lab's existing Ollama service."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        model: str | None = None,
        timeout_seconds: float = 120.0,
    ) -> None:
        configured_base = base_url or os.environ.get(
            "OLLAMA_URL", "http://ollama:11434"
        )
        self.base_url = configured_base.rstrip("/")
        self.model = model or os.environ.get("OLLAMA_EMBED_MODEL", "bge-m3:latest")
        self.timeout = httpx.Timeout(timeout_seconds)

    async def embed(self, inputs: Sequence[str]) -> list[list[float]]:
        texts = list(inputs)
        if not texts or any(not isinstance(text, str) or not text.strip() for text in texts):
            raise ValueError("embedding input must contain one or more non-empty strings")

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/embed",
                    json={"model": self.model, "input": texts},
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise EmbeddingBackendError("Ollama embedding request failed") from exc

        embeddings = payload.get("embeddings") if isinstance(payload, dict) else None
        returned_model = payload.get("model") if isinstance(payload, dict) else None
        if returned_model != self.model:
            raise EmbeddingBackendError(
                "Ollama returned embeddings from an unexpected model"
            )
        if not isinstance(embeddings, list) or len(embeddings) != len(texts):
            raise EmbeddingBackendError("Ollama returned an invalid embedding batch")

        dimensions: int | None = None
        validated: list[list[float]] = []
        for vector in embeddings:
            if not isinstance(vector, list) or not vector:
                raise EmbeddingBackendError("Ollama returned an empty embedding vector")
            if dimensions is None:
                dimensions = len(vector)
            elif len(vector) != dimensions:
                raise EmbeddingBackendError("Ollama returned inconsistent embedding dimensions")

            converted: list[float] = []
            for value in vector:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise EmbeddingBackendError("Ollama returned a non-numeric embedding value")
                numeric = float(value)
                if not math.isfinite(numeric):
                    raise EmbeddingBackendError("Ollama returned a non-finite embedding value")
                converted.append(numeric)
            validated.append(converted)

        return validated
