"""Business evidence must follow actual execution, not learner claims."""
from contextlib import contextmanager
import importlib.util
from pathlib import Path
import unittest

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'llm-security-control-plane/guided-labs/h17-telemetry/workflow.py'
spec = importlib.util.spec_from_file_location('p17_workflow', PATH)
workflow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workflow)


class P17WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.provider = TracerProvider()
        self.exporter = InMemorySpanExporter()
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.tracer = self.provider.get_tracer('p17-test')
        self.addCleanup(self.provider.shutdown)

    @contextmanager
    def stage(self, name):
        with self.tracer.start_as_current_span(name):
            yield

    def test_actual_branches_and_sdk_identity(self):
        cases = [('reader', 'notice_lookup', ['authenticate', 'authorize', 'notice_lookup'], 1),
                 ('reader', 'notice_publish', ['authenticate', 'authorize'], 0),
                 ('anonymous', 'notice_lookup', ['authenticate'], 0)]
        for principal, action, expected, count in cases:
            with self.subTest(principal=principal, action=action):
                op = workflow.BusinessOperation('request-' + principal + action, principal, action)
                with self.tracer.start_as_current_span('security.request') as root:
                    result = op.run(self.stage)
                    root_context = root.get_span_context()
                ledger = op.ledger()
                self.assertEqual([s['stage'] for s in ledger['stages']], expected)
                self.assertEqual(result['downstream_count'], count)
                self.assertEqual(result['decision'], 'allow' if count else 'block')
                self.assertEqual(ledger['invocations'], 1)
                self.assertEqual(len(ledger['closures']), 1)
                exported = {f'{s.context.span_id:016x}': s for s in self.exporter.get_finished_spans()}
                for stage in ledger['stages']:
                    self.assertEqual(stage['trace_id'], f'{root_context.trace_id:032x}')
                    self.assertEqual(exported[stage['span_id']].parent.span_id, root_context.span_id)

    def test_double_call_is_visible_in_independent_ledger(self):
        op = workflow.BusinessOperation('double', 'reader', 'notice_lookup')
        op.run(self.stage)
        op.run(self.stage)
        self.assertEqual(op.invocations, 2)
        self.assertEqual(len(op.downstream_calls), 2)
        self.assertEqual(len(op.closures), 2)

    def test_failure_does_not_manufacture_closed_or_downstream(self):
        op = workflow.BusinessOperation('failed', 'reader', 'notice_lookup')
        def broken_stage(name):
            raise RuntimeError('instrumentation failure')
        with self.assertRaises(RuntimeError):
            op.run(broken_stage)
        self.assertEqual(op.invocations, 1)
        self.assertEqual(op.closures, [])
        self.assertEqual(op.downstream_calls, [])


if __name__ == '__main__':
    unittest.main()
