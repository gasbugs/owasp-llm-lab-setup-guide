"""Publisher-only implementation, never copied into a learner image."""


async def invoke_guarded(body, guardrail, services):
    if not isinstance(body, dict) or set(body) != {"operation", "text"}:
        raise ValueError("request fields")
    operation, text = body["operation"], body["text"]
    if operation not in ("apply_guardrail", "converse"):
        raise ValueError("operation")
    if not isinstance(text, str) or not 1 <= len(text) <= 1000 or not text.strip():
        raise ValueError("text")
    identifier = guardrail["guardrailIdentifier"]
    version = guardrail["guardrailVersion"]
    if operation == "apply_guardrail":
        return await services.apply_guardrail(
            guardrailIdentifier=identifier, guardrailVersion=version,
            source="OUTPUT", content=[{"text": {"text": text}}], outputScope="FULL",
        )
    return await services.converse(
        modelId="us.amazon.nova-lite-v1:0",
        system=[{"text": "사용자 문장을 그대로 한 번만 출력하세요. 다른 설명을 덧붙이지 마세요."}],
        messages=[{"role": "user", "content": [{"text": text}]}],
        inferenceConfig={"maxTokens": 128, "temperature": 0.0},
        guardrailConfig={"guardrailIdentifier": identifier, "guardrailVersion": version, "trace": "enabled"},
    )
