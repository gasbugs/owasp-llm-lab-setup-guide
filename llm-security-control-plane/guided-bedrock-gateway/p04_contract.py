"""Server-owned P04 invocation boundary; never fills in missing learner arguments."""
import json

PRACTICE_ID = "P04"
ACTIVITY_ID = "H04"
CONTRACT_VERSION = "p04-guardrail-v1"
MODEL_ID = "us.amazon.nova-lite-v1:0"
SYSTEM_TEXT = "사용자 문장을 그대로 한 번만 출력하세요. 다른 설명을 덧붙이지 마세요."


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()


def expected_arguments(body, guardrail):
    if (not isinstance(body, dict) or set(body) != {"operation", "text"}
            or body["operation"] not in ("apply_guardrail", "converse")
            or not isinstance(body["text"], str) or not 1 <= len(body["text"]) <= 1000
            or not body["text"].strip()):
        raise ValueError("no provider operation is permitted for this input")
    if (not isinstance(guardrail, dict)
            or set(guardrail) != {"guardrailIdentifier", "guardrailVersion"}
            or not isinstance(guardrail["guardrailIdentifier"], str)
            or not guardrail["guardrailIdentifier"].isascii()
            or not 1 <= len(guardrail["guardrailIdentifier"]) <= 2048
            or not guardrail["guardrailIdentifier"].strip()
            or guardrail["guardrailVersion"] != "DRAFT"):
        raise ValueError("invalid server-owned policy")
    if body["operation"] == "apply_guardrail":
        return {**guardrail, "source": "OUTPUT",
                "content": [{"text": {"text": body["text"]}}], "outputScope": "FULL"}
    return {
        "modelId": MODEL_ID, "system": [{"text": SYSTEM_TEXT}],
        "messages": [{"role": "user", "content": [{"text": body["text"]}]}],
        "inferenceConfig": {"maxTokens": 128, "temperature": 0.0},
        "guardrailConfig": {**guardrail, "trace": "enabled"},
    }


def validate_invocation(operation, payload, *, body, guardrail):
    expected = expected_arguments(body, guardrail)
    if operation != body["operation"] or not isinstance(payload, dict):
        raise ValueError("operation does not match the registered case")
    candidate = json.loads(canonical(payload))
    if operation == "converse":
        config = candidate.get("inferenceConfig")
        if (not isinstance(config, dict)
                or type(config.get("maxTokens")) is not int
                or type(config.get("temperature")) not in (int, float)):
            raise ValueError("invalid inference configuration")
        # A numeric zero is equivalent; booleans and string coercion are not.
        if config["temperature"] == 0:
            config["temperature"] = 0.0
    if canonical(candidate) != canonical(expected):
        raise ValueError("arguments do not match the registered policy and input")
    # Validation does not inject the answer into the request.
    return json.loads(canonical(payload))
