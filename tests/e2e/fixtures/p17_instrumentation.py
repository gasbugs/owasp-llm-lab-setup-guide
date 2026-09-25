"""Publisher implementation; never copied into a learner Starter image."""
from contextlib import contextmanager
import json


def observe_request(request_id, run_business, tracer, logger, counter):
    sequence = 0
    with tracer.start_as_current_span('security.request', attributes={'request_id': request_id}) as root:
        trace_id = f'{root.get_span_context().trace_id:032x}'

        @contextmanager
        def stage(name):
            nonlocal sequence
            sequence += 1
            with tracer.start_as_current_span(name, attributes={
                'request_id': request_id, 'sequence': sequence,
            }):
                yield

        result = run_business(stage)
        root.set_attribute('decision', result['decision'])
        root.set_attribute('stop_stage', result['stop_stage'] or '')
        root.set_attribute('stage_count', sequence)
        logger.info(json.dumps({'request_id': request_id, 'trace_id': trace_id,
                               'decision': result['decision'], 'stop_stage': result['stop_stage']}),
                    extra={'request_id': request_id, 'trace_id': trace_id})
        counter.labels(result['decision']).inc()
        return result
