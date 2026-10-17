"""P19 Starter: implement request-specific evidence analysis."""


def analyze_incident(bundle, request_id):
    """Analyze one request from normalized evidence; reject contradictions."""
    # TODO 1: logs·spans·closures·downstream_calls 목록에서 대상 request_id만 고르세요.
    # 대상 외 행은 다른 필드가 비어 있어도 검사하지 마세요.
    # TODO 2: 결정 Log와 종료 closure가 각각 한 건인지, trace_id가 같은지 확인하세요.
    # TODO 3: 단계 Span의 정수 sequence를 1부터 연속으로 확인하고 stages를 순서대로 만드세요.
    # TODO 4: allow/block·stop_stage·closed와 실제 downstream 호출 수를 대조하세요.
    # 모순이나 누락은 ValueError로 거부하고, 확인된 여섯 필드를 dict로 반환하세요.
    raise NotImplementedError('P19 incident analysis is not implemented')
