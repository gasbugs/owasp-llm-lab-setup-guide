"""P04: validate the request and connect the supplied Guardrail to the chosen API."""


async def invoke_guarded(body, guardrail, services):
    # 입력이 딕셔너리 형태인지 확인
    if not isinstance(body, dict):
        raise ValueError("Invalid body type")

    # body에는 operation과 text 두 필드만 허용
    if set(body.keys()) != {"operation", "text"}:
        raise ValueError("Invalid fields in body")

    operation = body.get("operation")
    text = body.get("text")

    # operation 타입 및 값 검사 (리스트 등 비문자열 입력 시 ValueError 발생)
    if not isinstance(operation, str) or operation not in {"apply_guardrail", "converse"}:
        raise ValueError("Invalid operation")

    # text 검사: 공백만으로 이루어지지 않은 1~1000자 문자열 (앞뒤 공백 유지)
    if not isinstance(text, str) or not text.strip() or len(text) < 1 or len(text) > 1000:
        raise ValueError("Invalid text")

    # guardrail 정보 확인
    if not isinstance(guardrail, dict) or "guardrailIdentifier" not in guardrail or "guardrailVersion" not in guardrail:
        raise ValueError("Invalid guardrail configuration")

    guardrail_identifier = guardrail["guardrailIdentifier"]
    guardrail_version = guardrail["guardrailVersion"]

    if operation == "apply_guardrail":
        # 단독 검사: apply_guardrail 호출 (content 구조 수정 반영)
        response = await services.apply_guardrail(
            guardrailIdentifier=guardrail_identifier,
            guardrailVersion=guardrail_version,
            source="OUTPUT",
            content=[{"text": {"text": text}}],
            outputScope="FULL"
        )
        return response

    elif operation == "converse":
        # 모델 요청: converse 호출
        response = await services.converse(
            modelId="us.amazon.nova-lite-v1:0",
            messages=[{"role": "user", "content": [{"text": text}]}],
            system=[{"text": "사용자 문장을 그대로 한 번만 출력하세요. 다른 설명을 덧붙이지 마세요."}],
            inferenceConfig={
                "maxTokens": 128,
                "temperature": 0
            },
            guardrailConfig={
                "guardrailIdentifier": guardrail_identifier,
                "guardrailVersion": guardrail_version,
                "trace": "enabled"
            }
        )
        return response
