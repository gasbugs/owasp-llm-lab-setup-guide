"""P04: validate the request and connect the supplied Guardrail to the chosen API."""


async def invoke_guarded(body, guardrail, services):
    # 제공 흐름: 입력의 필드·타입·길이를 서비스 호출 전에 확인합니다.
    if not isinstance(body, dict) or set(body) != {"operation", "text"}:
        raise ValueError("operation and text required")
    operation, text = body["operation"], body["text"]
    if operation not in ("apply_guardrail", "converse"):
        raise ValueError("invalid operation")
    if not isinstance(text, str) or not text.strip() or len(text) > 1000:
        raise ValueError("invalid text")

    if operation == "apply_guardrail":
        # TODO 2: 서버가 준 정책으로 services.apply_guardrail()을 한 번 호출하세요.
        # source="OUTPUT", outputScope="FULL"이며 응답을 response에 받습니다.
        raise NotImplementedError("P04 implementation required")
    else:
        # TODO 3: 같은 정책을 guardrailConfig에 넣어 services.converse()를
        # 한 번 호출하고 응답을 response에 받으세요.
        raise NotImplementedError("P04 implementation required")

    # 제공 흐름: 응답을 가공하거나 서비스 오류를 감추지 않습니다.
    return response
