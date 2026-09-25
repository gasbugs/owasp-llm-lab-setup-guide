"""Execute P17 learner instrumentation in a bounded, credential-free worker."""
import hashlib
import importlib.util
import json
import logging
import resource
from pathlib import Path
import sys
import time
import uuid

from prometheus_client import CollectorRegistry, Counter, generate_latest

from workflow import BusinessOperation


class Signals:
    def __init__(self):
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
        resource = Resource.create({'service.name': 'guided-h17-telemetry'})
        self.trace_provider = TracerProvider(resource=resource)
        self.trace_provider.add_span_processor(BatchSpanProcessor(
            OTLPSpanExporter(endpoint='http://alloy:4318/v1/traces', timeout=3)))
        self.log_provider = LoggerProvider(resource=resource)
        self.log_provider.add_log_record_processor(BatchLogRecordProcessor(
            OTLPLogExporter(endpoint='http://alloy:4318/v1/logs', timeout=3)))
        self.tracer = self.trace_provider.get_tracer('p17')
        self.logger = logging.Logger('p17-decisions', level=logging.INFO)
        self.logger.addHandler(LoggingHandler(logger_provider=self.log_provider))

    def flush(self):
        traces = self.trace_provider.force_flush(timeout_millis=5000)
        logs = self.log_provider.force_flush(timeout_millis=5000)
        return traces and logs

    def close(self):
        self.trace_provider.shutdown()
        self.log_provider.shutdown()


def run_suite(source, baseline, signals):
    registry = CollectorRegistry()
    counter = Counter('guided_p17_decisions_total', 'P17 business decisions',
                      ['decision'], registry=registry)
    for decision in ('allow', 'block'):
        counter.labels(decision).inc(baseline[decision])
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    result = {'source_digest': digest, 'cases': [], 'closed': False}
    try:
        spec = importlib.util.spec_from_file_location('p17_learner', source)
        learner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(learner)
        for principal, action in (('reader', 'notice_lookup'), ('reader', 'notice_publish'),
                                  ('anonymous', 'notice_lookup')):
            request_id = str(uuid.uuid4())
            operation = BusinessOperation(request_id, principal, action)
            case = {'request_id': request_id, 'principal': principal, 'action': action,
                    'started_ns': time.time_ns()}
            try:
                case['returned'] = learner.observe_request(
                    request_id, operation.run, signals.tracer, signals.logger, counter)
                case['execution_status'] = 'returned'
            except NotImplementedError:
                case['execution_status'] = 'not_implemented'
            except Exception as exc:
                case['execution_status'] = 'error'
                case['error_type'] = type(exc).__name__
            case.update(finished_ns=time.time_ns(), ledger=operation.ledger())
            result['cases'].append(case)
        result['closed'] = True
        result['export_flushed'] = signals.flush()
    except Exception as exc:
        result['execution_error'] = type(exc).__name__
    # These values come from the learner's actual SDK counter, not expected outcomes.
    result['metrics'] = generate_latest(registry).decode()
    result['counter_values'] = {
        decision: registry.get_sample_value('guided_p17_decisions_total', {'decision': decision})
        for decision in ('allow', 'block')}
    return result


def main():
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_FSIZE, (262144, 262144))
    body = json.load(sys.stdin)
    signals = Signals()
    try:
        result = run_suite(Path(body['source']), body['baseline'], signals)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    finally:
        signals.close()


if __name__ == '__main__':
    main()
