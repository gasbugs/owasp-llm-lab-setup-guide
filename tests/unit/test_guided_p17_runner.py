"""P17 actual learner execution and real SDK export, without product servers."""
import importlib.util
import json
import logging
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor, InMemoryLogExporter

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'llm-security-control-plane/guided-labs/h17-telemetry'
fault_spec = importlib.util.spec_from_file_location('p17_faults', ROOT / 'tests/e2e/p17_faults.py')
faults = importlib.util.module_from_spec(fault_spec)
fault_spec.loader.exec_module(faults)
with patch.dict(sys.modules):
    sys.modules.pop('workflow', None)
    sys.path.insert(0, str(BASE))
    try:
        spec = importlib.util.spec_from_file_location('p17_runner', BASE / 'runner.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
    finally:
        sys.path.pop(0)


class TestSignals:
    def __init__(self):
        resource = Resource.create({'service.name': 'guided-h17-telemetry'})
        self.trace_provider = TracerProvider(resource=resource)
        self.spans = InMemorySpanExporter()
        self.trace_provider.add_span_processor(SimpleSpanProcessor(self.spans))
        self.log_provider = LoggerProvider(resource=resource)
        self.logs = InMemoryLogExporter()
        self.log_provider.add_log_record_processor(SimpleLogRecordProcessor(self.logs))
        self.tracer = self.trace_provider.get_tracer('test')
        self.logger = logging.Logger('p17-test', level=logging.INFO)
        self.logger.addHandler(LoggingHandler(logger_provider=self.log_provider))

    def flush(self):
        return self.trace_provider.force_flush() and self.log_provider.force_flush()

    def close(self):
        self.trace_provider.shutdown()
        self.log_provider.shutdown()


class P17RunnerTests(unittest.TestCase):
    def setUp(self):
        self.signals = TestSignals()
        self.addCleanup(self.signals.close)

    def run_source(self, source, baseline=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'instrumentation.py'
            path.write_text(source)
            return runner.run_suite(path, baseline or {'allow': 0, 'block': 0}, self.signals)

    def test_real_signals_and_original_business_return(self):
        self.check_real_signals('p17_instrumentation.py')

    def test_class_based_alternative_preserves_real_signals(self):
        self.check_real_signals('p17_instrumentation_alternative.py')

    def check_fault(self, fault, expected_logs):
        source = (ROOT / 'tests/e2e/fixtures/p17_instrumentation.py').read_text()
        result = self.run_source(faults.inject(source, fault))
        self.assertTrue(result['closed'])
        self.assertEqual(result['counter_values'], {'allow': 1, 'block': 2})
        self.assertEqual([c['returned']['downstream_count'] for c in result['cases']], [1, 0, 0])
        self.assertEqual(len(self.signals.spans.get_finished_spans()), 9)
        logs = self.signals.logs.get_finished_logs()
        self.assertEqual(len(logs), expected_logs)
        return [json.loads(row.log_record.body) for row in logs]

    def test_missing_log_fault_keeps_real_business_and_other_signals(self):
        self.check_fault('missing-log', 0)

    def test_duplicate_log_fault_keeps_real_business_and_other_signals(self):
        self.check_fault('duplicate-log', 6)

    def test_fixed_block_fault_does_not_change_real_business(self):
        self.assertEqual([r['decision'] for r in self.check_fault('fixed-block-log', 3)], ['block'] * 3)

    def test_fault_fixture_drift_is_not_silently_ignored(self):
        with self.assertRaises(ValueError):
            faults.inject('def observe_request(): pass', 'missing-log')

    def check_real_signals(self, filename):
        source = (ROOT / 'tests/e2e/fixtures' / filename).read_text()
        result = self.run_source(source, {'allow': 4, 'block': 8})
        self.assertTrue(result['closed'])
        self.assertEqual(result['counter_values'], {'allow': 5, 'block': 10})
        self.assertEqual(len(self.signals.spans.get_finished_spans()), 9)
        self.assertEqual(len(self.signals.logs.get_finished_logs()), 3)
        self.assertEqual([r['returned']['downstream_count'] for r in result['cases']], [1, 0, 0])
        self.assertTrue(all(r['execution_status'] == 'returned' for r in result['cases']))
        self.assertIn('guided_p17_decisions_total{decision="block"} 10.0', result['metrics'])

    def test_starter_never_creates_business_or_signals(self):
        result = self.run_source((BASE / 'instrumentation.py').read_text())
        self.assertEqual([r['execution_status'] for r in result['cases']], ['not_implemented'] * 3)
        self.assertEqual(result['counter_values'], {'allow': 0, 'block': 0})
        self.assertTrue(all(r['ledger']['invocations'] == 0 for r in result['cases']))
        self.assertEqual(self.signals.spans.get_finished_spans(), ())

    def test_syntax_error_is_execution_error_not_closed_success(self):
        result = self.run_source('def broken(:\n')
        self.assertEqual(result['execution_error'], 'SyntaxError')
        self.assertFalse(result['closed'])

    def test_return_mutation_cannot_change_business_snapshot(self):
        source = (ROOT / 'tests/e2e/fixtures/p17_instrumentation.py').read_text()
        source = source.replace('return result', "result['result'] = None\n        return result")
        result = self.run_source(source)
        first = result['cases'][0]
        self.assertIsNone(first['returned']['result'])
        self.assertIsNotNone(first['ledger']['closures'][0]['result'])


if __name__ == '__main__':
    unittest.main()
