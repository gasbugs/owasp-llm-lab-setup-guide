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

    # ① 허용한 요청은 원문을 유지하고 출력 상한만 제한한다.
    return client.converse(
        modelId="us.amazon.nova-lite-v1:0",
        messages=[{"role": "user", "content": [{"text": message}]}],
        inferenceConfig={"maxTokens": min(tokens, 128), "temperature": 0.0},
    )
