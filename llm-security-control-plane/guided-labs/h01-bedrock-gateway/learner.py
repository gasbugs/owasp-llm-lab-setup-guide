"""P01 learner artifact: validate a chat request, then call Bedrock Converse."""


def handle_request(body: dict, client) -> dict:
    """Return the raw Converse response; raise ValueError for an invalid body.

    body contains only the client request, not grading metadata or credentials.
    client.converse(**kwargs) has the Boto3 Converse interface.
    Implement validation, request limits, and the actual invocation here.
    """
    # TODO 1: body의 두 필드와 각 타입·범위를 모델 호출 전에 검사하세요.
    # TODO 2: 요청한 출력 상한을 128 이하로 제한하고 그 양을 예약하세요.
    # TODO 3: 원문 질문과 제한한 상한으로 Converse를 한 번 호출하세요.
    # 호출 실패 시 예약을 취소하고 같은 오류를 다시 전달하세요.
    # TODO 4: 성공한 응답의 실제 outputTokens로 예산을 정산하세요.
    # Converse가 돌려준 응답 dict 전체를 바꾸지 말고 반환하세요.
    raise NotImplementedError("P01 request handling is not implemented")
