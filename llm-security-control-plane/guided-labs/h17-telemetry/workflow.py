"""Provided P17 business fixture, independent of the learner's telemetry.

The principal is a server-owned synthetic identity, not a login implementation.
No LLM or prompt-injection detector is involved.
"""
from copy import deepcopy
from opentelemetry import trace


class BusinessOperation:
    def __init__(self, request_id, principal, action):
        self.request_id = request_id
        self.principal = principal
        self.action = action
        self.invocations = 0
        self.stages = []
        self.downstream_calls = []
        self.closures = []

    def _record_stage(self, name):
        context = trace.get_current_span().get_span_context()
        self.stages.append({
            'request_id': self.request_id, 'stage': name,
            'sequence': len(self.stages) + 1,
            'trace_id': f'{context.trace_id:032x}',
            'span_id': f'{context.span_id:016x}',
        })

    def run(self, stage):
        self.invocations += 1
        stop = None
        result = None
        with stage('authenticate'):
            self._record_stage('authenticate')
            authenticated = self.principal == 'reader'
        if not authenticated:
            stop = 'authenticate'
        else:
            with stage('authorize'):
                self._record_stage('authorize')
                authorized = self.action == 'notice_lookup'
            if not authorized:
                stop = 'authorize'
            else:
                with stage('notice_lookup'):
                    self._record_stage('notice_lookup')
                    result = {'notice_id': 'p17-training-notice', 'text': 'P17 교육용 공지입니다.'}
                    self.downstream_calls.append({**self.stages[-1], 'result': deepcopy(result)})
        output = {'decision': 'block' if stop else 'allow', 'stop_stage': stop,
                  'downstream_count': len(self.downstream_calls), 'result': result}
        self.closures.append(deepcopy({'request_id': self.request_id, 'closed': True, **output}))
        return output

    def ledger(self):
        return {'request_id': self.request_id, 'invocations': self.invocations,
                'stages': self.stages, 'downstream_calls': self.downstream_calls,
                'closures': self.closures}
