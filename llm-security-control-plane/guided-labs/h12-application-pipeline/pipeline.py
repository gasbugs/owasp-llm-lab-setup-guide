"""P12: 제공된 단계 순서에 실제 서비스 호출을 연결하세요."""

import json


async def handle_request(request, services):
    """각 단계가 거부되면 즉시 멈추고 뒤 서비스를 호출하지 않습니다."""
    # TODO 1: authenticate(request["credential"])의 결과를 authenticated에 받으세요.
    raise NotImplementedError("P12 authentication call required")
    if not authenticated:
        return {"status": 401, "text": ""}

    # TODO 2: authorize(request["tenant"])의 결과를 authorized에 받으세요.
    raise NotImplementedError("P12 authorization call required")
    if not authorized:
        return {"status": 403, "text": ""}

    # TODO 3: input_privacy 결과를 message에 받고 input_rail의 판정을 input_allowed에 받으세요.
    raise NotImplementedError("P12 input protection calls required")
    if not input_allowed:
        return {"status": 403, "text": ""}

    # TODO 4: message로 검색하고 원문을 context에 받으세요.
    raise NotImplementedError("P12 retrieval call required")
    if not context:
        return {"status": 404, "text": ""}

    # TODO 5: retrieval_rail의 판정을 retrieval_allowed에 받으세요.
    raise NotImplementedError("P12 retrieval rail call required")
    if not retrieval_allowed:
        return {"status": 403, "text": ""}

    prompt = json.dumps({"question": message, "context": context}, ensure_ascii=False, separators=(",", ":"))
    # TODO 6: Main 호출 결과를 answer에, output_rail 판정을 output_allowed에 받으세요.
    raise NotImplementedError("P12 model and output rail calls required")
    if not output_allowed:
        return {"status": 403, "text": ""}

    # TODO 7: output_privacy 결과를 safe_answer에 받으세요.
    raise NotImplementedError("P12 output privacy call required")
    return {"status": 200, "text": safe_answer}
