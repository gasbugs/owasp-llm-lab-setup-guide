"""Independent publisher implementation; excluded from learner images."""
import json


class RequestStages:
    def __init__(self, tracer, request_id):
        self.tracer = tracer
        self.request_id = request_id
        self.count = 0

    def __call__(self, name):
        self.count += 1
        return self.tracer.start_as_current_span(name, attributes={
            'sequence': self.count, 'request_id': self.request_id,
        })


def observe_request(request_id, run_business, tracer, logger, counter):
    stages = RequestStages(tracer, request_id)
    with tracer.start_as_current_span('security.request') as request_span:
        request_span.set_attribute('request_id', request_id)
        outcome = run_business(stages)
        request_span.set_attributes({
            'stage_count': stages.count,
            'stop_stage': outcome['stop_stage'] or '',
            'decision': outcome['decision'],
        })
        correlation = {
            'trace_id': format(request_span.get_span_context().trace_id, '032x'),
            'request_id': request_id,
        }
        event = dict(correlation, decision=outcome['decision'],
                     stop_stage=outcome['stop_stage'])
        logger.info(json.dumps(event, sort_keys=True))
        counter.labels(decision=outcome['decision']).inc(1)
    return outcome
