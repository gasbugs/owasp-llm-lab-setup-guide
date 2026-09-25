"""Publisher-only P19 actual OTLP->Loki/Tempo collection; no learner verdict."""
import importlib.util
import json
import logging
from pathlib import Path
import sys
import time

import httpx
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter

ROOT = Path('llm-security-control-plane')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    workflow = load('p19_workflow', 'guided-labs/h19-incident-investigation/workflow.py')
    collection = load('p19_collection', 'guided-labs/h19-incident-investigation/collection.py')
    results = load('p19_results', 'guided-evidence-verifier/p19_results.py')
    deadline = time.monotonic() + 90
    pending = ['http://loki:3100/ready', 'http://tempo:3200/ready']
    with httpx.Client(timeout=3, trust_env=False) as client:
        while pending and time.monotonic() < deadline:
            for url in list(pending):
                try:
                    if client.get(url).status_code == 200:
                        pending.remove(url)
                except httpx.HTTPError:
                    pass
            if pending:
                time.sleep(1)
        assert not pending, f'products not ready: {pending}'
    resource = Resource.create({'service.name': 'guided-h19-investigation'})
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint='http://alloy:4318/v1/traces')))
    log_provider = LoggerProvider(resource=resource)
    log_provider.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter(endpoint='http://alloy:4318/v1/logs')))
    logger = logging.getLogger('p19-product-check')
    logger.setLevel(logging.INFO)
    logger.addHandler(LoggingHandler(logger_provider=log_provider))
    try:
        store = workflow.NoticeStore()
        cases = workflow.run_requests(tracer_provider.get_tracer('p19'), logger, store)
        assert tracer_provider.force_flush() and log_provider.force_flush()
        observed = collection.collect(cases, store.calls)
        analyses = [results.expected_analysis(observed['bundle'], case['request_id']) for case in cases]
        assert [analysis['stop_stage'] for analysis in analyses] == [None, 'authorize', 'authenticate']
        assert [analysis['downstream_count'] for analysis in analyses] == [1, 0, 0]
        proof = {'scope': 'actual products and fixture; no learner, HTTP verifier, Browser, or AWS',
                 'cases': cases, 'downstream_calls': store.calls, **observed, 'analyses': analyses}
        Path(sys.argv[1]).write_text(json.dumps(proof, ensure_ascii=False, indent=2))
        print(json.dumps({'scope': proof['scope'], 'requests': len(cases),
                          'logs': len(observed['bundle']['logs']), 'stage_spans': len(observed['bundle']['spans']),
                          'stop_stages': [row['stop_stage'] for row in analyses]}, ensure_ascii=False))
    finally:
        tracer_provider.shutdown()
        log_provider.shutdown()


if __name__ == '__main__':
    main()
