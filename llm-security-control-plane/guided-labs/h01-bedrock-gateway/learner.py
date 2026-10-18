"""P01 learner artifact: validate a chat request, then call Bedrock Converse."""


def handle_request(body: dict, client) -> dict:
    """Return the raw Converse response; reject invalid input before model calls."""
    # 제공 흐름: 요청 형식을 먼저 확인합니다.
    if not isinstance(body, dict) or set(body) != {"message", "max_output_tokens"}:
        raise ValueError("invalid request fields")
    message = body["message"]
    requested = body["max_output_tokens"]
    if not isinstance(message, str) or not message.strip() or len(message) > 4000:
        raise ValueError("invalid message")
    if type(requested) is not int or not 1 <= requested <= 512:
        raise ValueError("invalid output limit")
    limit = requested
    if requested > 128:
        # TODO 2: 출력 상한을 서버 허용값으로 낮추세요.
        raise NotImplementedError("P01 output limit is not implemented")

    # TODO 2: client.reserve_budget(limit)으로 호출 전에 예산을 예약하고
    # 예약 ID를 reservation에 받으세요.
    raise NotImplementedError("P01 request handling is not implemented")
    try:
        # TODO 3: client.converse()에 원문 message·limit·정해진 모델과
        # temperature를 전달하고 응답 전체를 response에 받으세요.
        raise NotImplementedError("P01 Converse is not implemented")
    except Exception:
        # 제공 흐름: 모델 실패 시 예약을 취소하고 같은 오류를 전달합니다.
        client.cancel_budget(reservation)
        raise
    # TODO 4: response의 usage.outputTokens로 예약을 정산하세요.
    raise NotImplementedError("P01 settlement is not implemented")
    return response
