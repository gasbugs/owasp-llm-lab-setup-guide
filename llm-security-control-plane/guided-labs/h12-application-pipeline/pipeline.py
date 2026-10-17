"""Learner-owned P12 orchestration. The Starter deliberately performs no calls."""


async def handle_request(request, services):
    """Connect the provided services using their actual return values."""
    # TODO 1: authenticate와 authorize를 차례로 await하고 실패하면 즉시 401·403을 반환하세요.
    # TODO 2: 입력 privacy의 결과를 input_rail과 검색에 넘기고 거부되면 중단하세요.
    # TODO 3: 검색 결과가 빈 문자열이면 404로 중단한 뒤 문서를 retrieval_rail로 검사하세요.
    # TODO 4: 허용된 질문·문서를 JSON prompt로 묶어 Main을 호출하세요.
    # TODO 5: 답변을 output_rail로 검사한 뒤 output_privacy 결과를 200으로 반환하세요.
    # 401·403·404의 text는 빈 문자열이며 서비스 오류는 잡지 말고 전달하세요.
    raise NotImplementedError("P12 pipeline is not implemented")
