"""Ollama 래퍼 — history 지원."""
from __future__ import annotations

import os
from typing import List

import httpx


class LLMClient:
    def __init__(self) -> None:
        self.base = os.environ.get("OLLAMA_URL", "http://ollama:11434")
        self.model = os.environ.get("OLLAMA_MODEL", "llama3.1:8b-instruct-q4_K_M")
        self.timeout = httpx.Timeout(120.0)

    async def chat(self, system: str, user: str, history: List[dict] | None = None) -> str:
        messages = [{"role": "system", "content": system}]
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": user})

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            r = await client.post(
                f"{self.base}/api/chat",
                json={"model": self.model, "stream": False, "messages": messages},
            )
            r.raise_for_status()
            return r.json()["message"]["content"]
