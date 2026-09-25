"""Native NeMo model adapter bound to one P12 Gateway grant; no AWS credentials."""
import hashlib
import json
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from nemoguardrails.types import LLMResponse

MODEL_ID = "us.amazon.nova-lite-v1:0"
ROLES = {"input_rail", "retrieval_rail", "output_rail", "main"}


class GatewayModel:
    provider_name = "p12-bedrock-gateway"

    def __init__(self, base_url, suite_id, execution_id, role, capability, *, transport=None):
        url = urlsplit(base_url)
        if (url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password
                or url.query or url.fragment or url.path not in {"", "/"}):
            raise ValueError("invalid configured Gateway origin")
        if role not in ROLES or not isinstance(capability, str) or not 40 <= len(capability) <= 256 or not capability.isascii():
            raise ValueError("invalid role grant")
        self.suite_id, self.execution_id = str(UUID(suite_id)), str(UUID(execution_id))
        self.role, self._capability = role, capability
        self.model_name = f"{MODEL_ID}#p12-{role}"
        self.provider_url = base_url.rstrip("/")
        self._transport = transport
        self._attempted = False
        self.gateway_evidence = None

    async def generate_async(self, prompt, *, stop=None, **kwargs):
        if self._attempted:
            raise ValueError("model grant already attempted")
        maximum = 128 if self.role == "main" else 3
        if stop or set(kwargs) - {"temperature", "max_tokens"} or kwargs.get("temperature", 0.0) != 0.0 or kwargs.get("max_tokens", maximum) != maximum:
            raise ValueError("unsupported model parameters")
        if isinstance(prompt, list) and len(prompt) == 1 and isinstance(prompt[0], dict) and prompt[0].get("role") == "user":
            prompt = prompt[0].get("content")
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 40000:
            raise ValueError("one nonempty text prompt required")
        self._attempted = True
        body = {"suite_id": self.suite_id, "execution_id": self.execution_id,
                "role": self.role, "model": self.model_name, "prompt": prompt}
        try:
            async with httpx.AsyncClient(timeout=65, follow_redirects=False, trust_env=False, transport=self._transport) as client:
                async with client.stream("POST", self.provider_url + "/v1/p12/invoke",
                                         headers={"Authorization": "Bearer " + self._capability}, json=body) as response:
                    if response.status_code != 200:
                        raise ValueError("Gateway rejected invocation")
                    raw = bytearray()
                    async for part in response.aiter_bytes():
                        raw.extend(part)
                        if len(raw) > 131072:
                            raise ValueError("oversized Gateway response")
            result = json.loads(raw)
            if any(result.get(key) != body[key] for key in ("suite_id", "execution_id", "role", "model")):
                raise ValueError("Gateway invocation binding mismatch")
            text, evidence = result["text"], result["evidence"]
            if (not isinstance(text, str) or not text or len(text) > 32000
                    or evidence["actual_model_id"] != MODEL_ID
                    or not isinstance(evidence["provider_request_id"], str) or not evidence["provider_request_id"]
                    or evidence["response_digest"] != hashlib.sha256(text.encode()).hexdigest()
                    or evidence["response_bytes"] != len(text.encode())):
                raise ValueError("invalid Gateway evidence")
            request = {"modelId": MODEL_ID, "messages": [{"role": "user", "content": [{"text": prompt}]}],
                       "inferenceConfig": {"maxTokens": maximum, "temperature": 0.0}}
            expected = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            if result["request_digest"] != expected:
                raise ValueError("Gateway request binding mismatch")
            self.gateway_evidence = {"provider_request_id": evidence["provider_request_id"],
                                     "request_digest": expected, "response_digest": evidence["response_digest"],
                                     "capability_digest": hashlib.sha256(self._capability.encode()).hexdigest()}
            return LLMResponse(content=text, model=self.model_name, request_id=evidence["provider_request_id"])
        except Exception:
            raise ValueError("P12 Gateway invocation failed") from None

    async def stream_async(self, prompt, *, stop=None, **kwargs):
        raise ValueError("streaming is not supported for this grant")
        yield
