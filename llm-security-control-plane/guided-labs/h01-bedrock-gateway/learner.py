"""P01 learner artifact: validate a chat request, then call Bedrock Converse."""


def handle_request(body: dict, client) -> dict:
    """Return the raw Converse response; raise ValueError for an invalid body.

    body contains only the client request, not grading metadata or credentials.
    client.converse(**kwargs) has the Boto3 Converse interface.
    Implement validation, request limits, and the actual invocation here.
    """
    # raise NotImplementedError("P01 request handling is not implemented")
    # 1. 필드 검증: body가 딕셔너리가 아니거나, message와 max_output_tokens 외의 필드가 있으면 거부 (ValueError 발생)
    if not isinstance(body, dict):
        raise ValueError("Body must be a dictionary.")

    expected_keys = {"message", "max_output_tokens"}
    if set(body.keys()) != expected_keys:
        raise ValueError("Request must contain only 'message' and 'max_output_tokens'.")

    message = body.get("message")
    max_output_tokens = body.get("max_output_tokens")

    # 2. 메시지 조건 검증: 문자열 여부, 1~4,000자 길이, 공백만 있는 경우 거부
    if not isinstance(message, str):
        raise ValueError("message must be a string.")
    if not (1 <= len(message) <= 4000):
        raise ValueError("message length must be between 1 and 4000 characters.")
    if not message.strip():
        raise ValueError("message cannot be empty or whitespace-only.")

    # 3. 출력 요구 조건 검증: 불리언/실수 거부, 1~512 범위의 정수 여부 확인 (잘못된 요청은 모델 호출 전 ValueError 발생)
    if isinstance(max_output_tokens, bool) or not isinstance(max_output_tokens, int):
        raise ValueError("max_output_tokens must be an integer.")
    if not (1 <= max_output_tokens <= 512):
        raise ValueError("max_output_tokens must be between 1 and 512.")

    # 6. 출력 제한 처리: 128 이하면 그대로, 초과하면 128로 제한
    actual_limit = min(max_output_tokens, 128)

    # 7. 호출 전 예산(Budget) 예약
    reservation_id = client.reserve_budget(actual_limit)

    try:
        # 4 & 5. 모델 호출 설정: us.amazon.nova-lite-v1:0에 temperature=0.0, 원본 메시지 그대로 전달
        response = client.converse(
            modelId="us.amazon.nova-lite-v1:0",
            messages=[
                {
                    "role": "user",
                    "content": [{"text": message}]
                }
            ],
            inferenceConfig={
                "temperature": 0.0,
                "maxTokens": actual_limit
            }
        )

        output_tokens = response.get("usage", {}).get("outputTokens", 0)
        # 7. 성공 시 실제 사용량으로 예산 정산
        client.settle_budget(reservation_id, output_tokens)

        # 8. Converse 응답을 가공 없이 그대로 반환
        return response
    except Exception:
        # 7. 호출 실패 또는 예산 부족 오류 발생 시 예산 취소 후 오류 그대로 전달
        client.cancel_budget(reservation_id)
        raise
