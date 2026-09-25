"""Independent publisher-only implementation; never part of Starter images."""


async def invoke_guarded(body, guardrail, services):
    if not isinstance(body, dict):
        raise ValueError("object required")
    if sorted(body) != ["operation", "text"]:
        raise ValueError("fields")
    text = body["text"]
    if not isinstance(text, str):
        raise ValueError("string required")
    if len(text) < 1 or len(text) > 1000 or text.isspace():
        raise ValueError("text range")
    operation = body["operation"]
    if not isinstance(operation, str):
        raise ValueError("operation type")
    if operation not in ("apply_guardrail", "converse"):
        raise ValueError("operation value")

    policy = dict(guardrailIdentifier=guardrail["guardrailIdentifier"],
                  guardrailVersion=guardrail["guardrailVersion"])
    if operation == "converse":
        params = {
            "modelId": "us.amazon.nova-lite-v1:0",
            "messages": [{"content": [{"text": text}], "role": "user"}],
            "system": [{"text": "사용자 문장을 그대로 한 번만 출력하세요. 다른 설명을 덧붙이지 마세요."}],
            "inferenceConfig": dict(temperature=0.0, maxTokens=128),
            "guardrailConfig": dict(policy, trace="enabled"),
        }
        response = await services.converse(**params)
    else:
        params = dict(policy, outputScope="FULL", source="OUTPUT",
                      content=[{"text": {"text": text}}])
        response = await services.apply_guardrail(**params)
    return response
