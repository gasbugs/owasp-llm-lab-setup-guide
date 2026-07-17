"""Optional server-side proxy to a loopback Day 6 guardrail API."""

from __future__ import annotations

import os

import httpx


class GuardrailProxyError(RuntimeError):
    pass


class GuardrailProxy:
    def __init__(self) -> None:
        self.engine = os.getenv("GUARD_ENGINE", "off").strip().lower()
        if self.engine not in {"off", "llm-guard", "nemo"}:
            raise ValueError("GUARD_ENGINE must be off, llm-guard, or nemo")
        urls = {
            "llm-guard": os.getenv(
                "LLM_GUARD_URL", "http://host.containers.internal:18091"
            ),
            "nemo": os.getenv(
                "NEMO_GUARD_URL", "http://host.containers.internal:18092"
            ),
        }
        self.base_url = urls.get(self.engine)
        self.timeout = httpx.Timeout(240.0)

    @property
    def enabled(self) -> bool:
        return self.engine in {"llm-guard", "nemo"}

    async def chat(self, message: str) -> dict:
        if not self.enabled or self.base_url is None:
            raise GuardrailProxyError("guardrail proxy is disabled")
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url.rstrip('/')}/api/chat",
                    json={"message": message},
                )
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise GuardrailProxyError(
                f"{self.engine} guardrail API unavailable"
            ) from exc
        if not isinstance(data, dict) or not isinstance(data.get("guardrail"), dict):
            raise GuardrailProxyError("guardrail API returned an invalid contract")
        return data

    async def policy(self) -> dict:
        if not self.enabled or self.base_url is None:
            return {"guard_engine": "off", "guard_mode": "off"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url.rstrip('/')}/api/guardrails/policy"
                )
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise GuardrailProxyError(
                f"{self.engine} guardrail policy unavailable"
            ) from exc
        if not isinstance(data, dict):
            raise GuardrailProxyError("guardrail policy returned an invalid contract")
        return data

