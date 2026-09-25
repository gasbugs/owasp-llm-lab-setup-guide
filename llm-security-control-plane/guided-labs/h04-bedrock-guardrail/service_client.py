"""One bounded P04 API invocation; lifecycle and verifier credentials never enter here."""
import hashlib
import json
from urllib.parse import urlsplit
from uuid import UUID

import httpx


class ServiceError(RuntimeError):
    pass


class ServiceClient:
    def __init__(self, suite_id, execution_id, origin, capability):
        if str(UUID(suite_id)) != suite_id or str(UUID(execution_id)) != execution_id:
            raise ValueError("invalid execution identity")
        parsed = urlsplit(origin)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
                or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
            raise ValueError("invalid gateway origin")
        if not isinstance(capability, str) or not capability.isascii() or not 40 <= len(capability) <= 256:
            raise ValueError("invalid execution credential")
        self.suite_id, self.execution_id = suite_id, execution_id
        self.origin, self.capability = origin.rstrip("/"), capability
        self.calls = []

    def _invoke(self, operation, payload):
        call = {"operation": operation, "state": "error"}
        self.calls.append(call)
        try:
            if len(self.calls) > 1:
                raise ValueError("call limit")
            raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False).encode()
            if len(raw) > 32768:
                raise ValueError("request size")
            call["request_digest"] = hashlib.sha256(raw).hexdigest()
            with httpx.Client(timeout=60, follow_redirects=False, trust_env=False) as client:
                with client.stream("POST", self.origin + "/v1/p04/invoke",
                                   json={"suite_id": self.suite_id, "execution_id": self.execution_id,
                                         "operation": operation, "payload": payload},
                                   headers={"Authorization": "Bearer " + self.capability}) as response:
                    call["http_status"] = response.status_code
                    if response.status_code != 200:
                        raise ValueError("gateway error")
                    raw_response = bytearray()
                    for chunk in response.iter_bytes():
                        raw_response.extend(chunk)
                        if len(raw_response) > 32768:
                            raise ValueError("response size")
            result = json.loads(raw_response)
            if (not isinstance(result, dict) or result.get("suite_id") != self.suite_id
                    or result.get("execution_id") != self.execution_id or result.get("operation") != operation
                    or set(result) != {"suite_id", "execution_id", "operation", "response"}
                    or not isinstance(result["response"], dict)):
                raise ValueError("response binding")
            encoded = json.dumps(result["response"], sort_keys=True, ensure_ascii=False, allow_nan=False).encode()
            call.update(state="complete", response_digest=hashlib.sha256(encoded).hexdigest())
            return result["response"]
        except Exception:
            raise ServiceError("P04 Guardrail service failed") from None

    async def apply_guardrail(self, **kwargs):
        return self._invoke("apply_guardrail", kwargs)

    async def converse(self, **kwargs):
        return self._invoke("converse", kwargs)
