def handle_request(body: dict, client) -> dict:
    # ③ 계약에 없는 필드와 누락은 기본 거부한다.
    if set(body) != {"message", "max_output_tokens"}:
        raise ValueError("허용하지 않은 필드 또는 누락")
    message = body["message"]
    tokens = body["max_output_tokens"]

    # ② 잘못된 입력은 AWS를 호출하기 전에 명시적으로 차단한다.
    if not isinstance(message, str) or not message.strip() or len(message) > 4000:
        raise ValueError("메시지 형식 오류")
    if type(tokens) is not int or not 1 <= tokens <= 512:
        raise ValueError("출력 요청 형식 오류")

    # ① Provider 호출 전에 최대 사용량을 예약하고 실제 사용량으로 정산한다.
    effective = min(tokens, 128)
    reservation = client.reserve_budget(effective)
    try:
        result = client.converse(
            modelId="us.amazon.nova-lite-v1:0",
            messages=[{"role": "user", "content": [{"text": message}]}],
            inferenceConfig={"maxTokens": effective, "temperature": 0.0},
        )
    except Exception:
        client.cancel_budget(reservation)
        raise
    client.settle_budget(reservation, result["usage"]["outputTokens"])
    return result
