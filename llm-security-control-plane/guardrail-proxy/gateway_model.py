"""Credential-free proxy-side adapter for the isolated Bedrock Gateway."""

import os
import time
from types import SimpleNamespace

import httpx
from nemoguardrails.types import LLMResponse


MODEL_ID = "us.amazon.nova-lite-v1:0"


class CallTracker:
    def __init__(self):
        self.calls = []
        self.main_attempted = False


class GatewayModel:
    provider_name = "isolated-bedrock-gateway"

    def __init__(self, role, tracker):
        if role not in {"input_rail", "main", "output_rail"}:
            raise ValueError("unsupported model role")
        self.role = role
        self.tracker = tracker
        self.model_name = f"{MODEL_ID}#{'main' if role == 'main' else 'self_check'}"
        self._attempted = False

    def bind(self, **params):
        if set(params) - {"max_tokens", "temperature"}:
            raise ValueError("unsupported NeMo model parameters")
        return self

    async def ainvoke(self, messages):
        prompt = messages if isinstance(messages, str) else "\n".join(
            f"{getattr(message, 'type', 'user')}: {message.content}" for message in messages
        )
        result = await self.generate_async(prompt)
        return SimpleNamespace(
            content=result.content,
            response_metadata={"model_name": self.model_name, "request_id": result.request_id},
        )

    async def generate_async(self, prompt, *, stop=None, **kwargs):
        if self._attempted:
            raise ValueError("model role already attempted")
        if isinstance(prompt, list) and len(prompt) == 1 and isinstance(prompt[0], dict):
            prompt = prompt[0].get("content")
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 16000 or stop:
            raise ValueError("unsupported model prompt")
        self._attempted = True
        if self.role == "main":
            self.tracker.main_attempted = True
        maximum = 128 if self.role == "main" else 3
        body = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
            "max_tokens": maximum,
        }
        started = time.perf_counter()
        async with httpx.AsyncClient(timeout=75, trust_env=False) as client:
            response = await client.post(
                os.environ["GATEWAY_URL"] + "/v1/chat/completions",
                headers={"Authorization": "Bearer " + os.environ["PROXY_GATEWAY_TOKEN"]},
                json=body,
            )
        if response.status_code != 200:
            raise ValueError(f"gateway status {response.status_code}")
        result = response.json()
        content = result["choices"][0]["message"]["content"]
        usage = result["usage"]
        if (result.get("model") != MODEL_ID or not isinstance(content, str) or not content
                or len(content) > 8000 or any(type(usage.get(key)) is not int or usage[key] < 0
                for key in ("prompt_tokens", "completion_tokens"))):
            raise ValueError("invalid gateway response")
        self.tracker.calls.append({
            "role": self.role,
            "provider_request_id": result["bedrock"]["request_id"],
            "input_tokens": usage["prompt_tokens"],
            "output_tokens": usage["completion_tokens"],
            "elapsed_ms": round((time.perf_counter() - started) * 1000),
        })
        return LLMResponse(content=content, model=self.model_name, request_id=result["id"])

    async def stream_async(self, prompt, *, stop=None, **kwargs):
        raise ValueError("streaming is not available")
        yield
