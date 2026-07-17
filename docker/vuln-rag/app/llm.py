"""Ollama HTTP API 얇은 래퍼."""
from __future__ import annotations

import os
import httpx


class LLMClient:
    def __init__(self) -> None:
        self.base = os.environ.get("OLLAMA_URL", "http://ollama:11434")
        self.model = os.environ.get("OLLAMA_MODEL", "llama3.1:8b-instruct-q4_K_M")
        configured_num_predict = os.environ.get("OLLAMA_NUM_PREDICT")
        self.num_predict = (
            int(configured_num_predict) if configured_num_predict is not None else None
        )
        self.timeout = httpx.Timeout(120.0)

    async def chat(self, system: str, user: str) -> str:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            payload = {
                "model": self.model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            }
            if self.num_predict is not None:
                payload["options"] = {"num_predict": self.num_predict}
            r = await client.post(
                f"{self.base}/api/chat",
                json=payload,
            )
            r.raise_for_status()
            data = r.json()
            return data["message"]["content"]
