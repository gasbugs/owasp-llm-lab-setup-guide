"""P19: 제공된 행 선택·순서 검사 흐름에 사건 판정식을 채우세요."""


def analyze_incident(bundle, request_id):
    """요청 한 건의 증거만 연결하고 누락·모순은 ValueError로 거부합니다."""
    # TODO: 아래 골격을 채우기 시작할 때 이 미구현 표시를 제거하세요.
    raise NotImplementedError("P19 incident analysis is not implemented")
    # 제공 흐름: 다른 요청의 행은 필드가 비어 있어도 검사하지 않습니다.
    selected = {}
    for kind in ("logs", "spans", "closures", "downstream_calls"):
        selected[kind] = [row for row in bundle.get(kind, [])
                          if isinstance(row, dict) and row.get("request_id") == request_id]

    logs, spans = selected["logs"], selected["spans"]
    closures, calls = selected["closures"], selected["downstream_calls"]
    if len(logs) != 1 or len(closures) != 1:
        raise ValueError("decision log or closure missing")
    log, closure = logs[0], closures[0]
    if not log.get("trace_id") or log.get("trace_id") != closure.get("trace_id"):
        raise ValueError("trace mismatch")

    ordered = sorted(spans, key=lambda row: row.get("sequence", -1)
                     if type(row.get("sequence")) is int else -1)
    stages = []
    for expected, span in enumerate(ordered, start=1):
        if type(span.get("sequence")) is not int or span["sequence"] != expected:
            raise ValueError("stage sequence mismatch")
        # TODO 3: Span의 trace_id·stage를 검사하고 stages에 추가하세요.
        raise NotImplementedError('P19 stage validation required')

    # TODO 4: 결정·stop_stage·closed와 실제 downstream 호출 수를 대조하세요.
    # 모순이면 ValueError로 거부하고 확인된 여섯 필드를 반환하세요.
    raise NotImplementedError('P19 incident analysis is not implemented')
