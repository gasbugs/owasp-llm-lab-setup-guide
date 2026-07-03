"""Ollama HTTP API 얇은 래퍼."""
from __future__ import annotations

import os
import httpx


class LLMClient:
    def __init__(self) -> None:
        self.base = os.environ.get("OLLAMA_URL", "http://ollama:11434")
        self.model = os.environ.get("OLLAMA_MODEL", "llama3.1:8b-instruct-q4_K_M")
        self.timeout = httpx.Timeout(120.0)

    async def chat(self, system: str, user: str) -> str:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            r = await client.post(
                f"{self.base}/api/chat",
                json={
                    "model": self.model,
                    "stream": False,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
            )
            r.raise_for_status()
            data = r.json()
            return data["message"]["content"]
