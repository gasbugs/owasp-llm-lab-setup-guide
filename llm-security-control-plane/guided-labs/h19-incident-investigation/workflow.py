"""P19's provided synthetic notice service; observations follow actual branches.

No LLM, AWS or prompt-injection detector is represented by this fixture.
Authentication is a server-owned fixture identity, not a production login flow.
"""
from contextlib import contextmanager
import json
import time
import uuid


class NoticeStore:
    def __init__(self):
        self.calls = []

    def lookup(self, request_id, trace_id):
        result = {'notice_id': 'p19-training-notice', 'text': 'P19 교육용 공지입니다.'}
        self.calls.append({'request_id': request_id, 'trace_id': trace_id,
                           'operation': 'notice_lookup', 'result': result})
        return result


def handle_request(principal, action, tracer, logger, store):
    request_id = str(uuid.uuid4())
    started_ns = time.time_ns()
    sequence = 0
    stop_stage = None
    result = None
    with tracer.start_as_current_span('security.request', attributes={
        'request_id': request_id, 'hands_on': 'H19', 'fixture': 'notice-authorization',
    }) as root:
        trace_id = f'{root.get_span_context().trace_id:032x}'

        @contextmanager
        def stage(name):
            nonlocal sequence
            sequence += 1
            with tracer.start_as_current_span(name, attributes={
                'request_id': request_id, 'sequence': sequence,
            }) as span:
                yield span

        with stage('authenticate') as span:
            authenticated = principal == 'reader'
            span.set_attribute('accepted', authenticated)
        if not authenticated:
            stop_stage = 'authenticate'
        else:
            with stage('authorize') as span:
                authorized = action == 'notice_lookup'
                span.set_attribute('accepted', authorized)
            if not authorized:
                stop_stage = 'authorize'
            else:
                with stage('notice_lookup'):
                    result = store.lookup(request_id, trace_id)
        decision = 'block' if stop_stage else 'allow'
        root.set_attribute('decision', decision)
        root.set_attribute('stop_stage', stop_stage or '')
        root.set_attribute('stage_count', sequence)
        event = {'request_id': request_id, 'trace_id': trace_id, 'decision': decision,
                 'stop_stage': stop_stage, 'fixture': 'notice-authorization'}
        logger.info(json.dumps(event, ensure_ascii=False), extra={
            'request_id': request_id, 'trace_id': trace_id, 'hands_on': 'H19',
        })
    own_calls = [call for call in store.calls if call['request_id'] == request_id]
    return {**event, 'closed': True, 'downstream_count': len(own_calls), 'result': result,
            'started_ns': started_ns, 'finished_ns': time.time_ns()}


def run_requests(tracer, logger, store):
    return [handle_request(principal, action, tracer, logger, store)
            for principal, action in (('reader', 'notice_lookup'),
                                      ('reader', 'notice_publish'),
                                      ('anonymous', 'notice_lookup'))]
