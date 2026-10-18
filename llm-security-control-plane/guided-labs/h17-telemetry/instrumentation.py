"""P17: 제공된 Span·단계 흐름에 실제 계측 호출을 연결하세요."""

from contextlib import contextmanager
import json


def observe_request(request_id, run_business, tracer, logger, counter):
    """사업 로직을 한 번 실행하고 원래 결과를 그대로 반환합니다."""
    sequence = 0
    # TODO 1: tracer.start_as_current_span()으로 요청 root Span을 여세요.
    raise NotImplementedError('Implement request Log, Trace and Counter instrumentation')
    with root_span:
        @contextmanager
        def stage(name):
            nonlocal sequence
            sequence += 1
            # TODO 2: name과 sequence가 있는 child Span을 여세요.
            raise NotImplementedError('Implement child Span instrumentation')
            with child_span:
                yield

        result = run_business(stage)
        # TODO 3: root Span에 결정·중단 단계·단계 수를 기록하세요.
        # TODO 4: 같은 요청과 Trace의 구조화 Log 한 건을 남기세요.
        # TODO 5: decision만 label로 사용해 Counter를 한 번 증가시키세요.
        raise NotImplementedError('Implement decision signals')
        return result
