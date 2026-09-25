"""Provided SDK boundary; records actual calls without assigning a course verdict."""

from copy import deepcopy
import hashlib


MODEL_ID = "us.amazon.nova-lite-v1:0"


class InvocationError(RuntimeError):
    pass


class RecordingClient:
    def __init__(self, execution_id, sdk_client=None, sdk_client_factory=None):
        self.execution_id = execution_id
        self.sdk_client = sdk_client
        self.sdk_client_factory = sdk_client_factory
        self.calls = []
        self.results = []
        self.attempts = 0
        self.provider_attempts = 0

    def converse(self, **kwargs):
        self.attempts += 1
        if self.attempts > 1:
            raise InvocationError("only one provider call is allowed")
        self.calls.append(deepcopy(kwargs))
        config = kwargs.get("inferenceConfig", {})
        tokens = config.get("maxTokens")
        # Safety ceiling is not the learner's 128-token policy. Incorrect but
        # bounded policy values remain observable by the verifier.
        if kwargs.get("modelId") != MODEL_ID or type(tokens) is not int or not 1 <= tokens <= 512:
            raise InvocationError("provider sandbox boundary exceeded")
        if self.sdk_client is None and self.sdk_client_factory is not None:
            self.sdk_client = self.sdk_client_factory()
        self.provider_attempts += 1
        if self.sdk_client is not None:
            result = self.sdk_client.converse(**kwargs)
        else:
            messages = kwargs.get("messages", [])
            request_id = hashlib.sha256(f"{self.execution_id}:{kwargs!r}".encode()).hexdigest()[:24]
            count = tokens if "GUIDED-H01-RISK" in str(messages) else min(tokens, 32)
            result = {
                "ResponseMetadata": {"RequestId": f"contract-{request_id}"},
                "output": {"message": {"role": "assistant", "content": [{"text": "계약 테스트 응답입니다."}]}},
                "usage": {"inputTokens": 12, "outputTokens": count, "totalTokens": 12 + count},
                "stopReason": "max_tokens" if count == tokens else "end_turn",
            }
        self.results.append(deepcopy(result))
        return result

    def observed_result(self, returned):
        if self.attempts != 1 or len(self.calls) != 1 or len(self.results) != 1 or returned != self.results[0]:
            raise InvocationError("implementation must return the actual single-call response")
        result = self.results[0]
        if not result.get("ResponseMetadata", {}).get("RequestId") or not isinstance(result.get("usage"), dict):
            raise InvocationError("provider response evidence is incomplete")
        return deepcopy(result)
