"""P04: validate the request and connect the supplied Guardrail to the chosen API."""


async def invoke_guarded(body, guardrail, services):
    # TODO 1: body의 operation·text 타입과 허용 범위를 서비스 호출 전에 검사하세요.
    # TODO 2: apply_guardrail이면 서버가 준 정책으로 OUTPUT을 한 번 검사하세요.
    # TODO 3: converse이면 같은 정책을 guardrailConfig에 연결해 모델을 한 번 호출하세요.
    # TODO 4: 호출이 돌려준 응답 객체 전체를 바꾸지 말고 반환하세요.
    # 서비스 오류를 정상 응답으로 바꾸지 마세요.
    raise NotImplementedError("P04 implementation required")
