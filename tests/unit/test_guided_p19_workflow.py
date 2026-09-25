"""Actual fixture branches and OTEL SDK spans, not a live product test."""
import importlib.util
import json
import logging
from pathlib import Path
import unittest
from unittest.mock import Mock

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

ROOT = Path(__file__).resolve().parents[2] / 'llm-security-control-plane'


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


workflow = load('p19_workflow', 'guided-labs/h19-incident-investigation/workflow.py')
results = load('p19_results', 'guided-evidence-verifier/p19_results.py')


class P19WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.exporter = InMemorySpanExporter()
        self.provider = TracerProvider()
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.addCleanup(self.provider.shutdown)
        self.tracer = self.provider.get_tracer('p19-test')
        self.logger = Mock(spec=logging.Logger)
        self.store = workflow.NoticeStore()

    def run_requests(self):
        return workflow.run_requests(self.tracer, self.logger, self.store)

    def test_normal_and_two_denials_have_distinct_actual_boundaries(self):
        cases = self.run_requests()
        self.assertEqual([case['decision'] for case in cases], ['allow', 'block', 'block'])
        self.assertEqual([case['stop_stage'] for case in cases], [None, 'authorize', 'authenticate'])
        self.assertEqual([case['downstream_count'] for case in cases], [1, 0, 0])
        self.assertEqual(len(self.store.calls), 1)
        self.assertEqual(self.store.calls[0]['request_id'], cases[0]['request_id'])
        self.assertEqual(cases[0]['result']['notice_id'], 'p19-training-notice')
        self.assertTrue(all(case['closed'] for case in cases))
        self.assertEqual(len({case['trace_id'] for case in cases}), 3)

    def test_exported_spans_match_executed_branches_and_root_links(self):
        cases = self.run_requests()
        spans = self.exporter.get_finished_spans()
        expected = [('authenticate', 'authorize', 'notice_lookup'), ('authenticate', 'authorize'), ('authenticate',)]
        for case, names in zip(cases, expected):
            own = [span for span in spans if span.attributes['request_id'] == case['request_id']]
            root = next(span for span in own if span.name == 'security.request')
            stages = sorted([span for span in own if span is not root], key=lambda span: span.attributes['sequence'])
            self.assertEqual(tuple(span.name for span in stages), names)
            self.assertEqual([span.attributes['sequence'] for span in stages], list(range(1, len(names) + 1)))
            self.assertIsNone(root.parent)
            self.assertEqual(root.attributes['decision'], case['decision'])
            for span in stages:
                self.assertEqual(span.parent.span_id, root.context.span_id)
                self.assertEqual(f'{span.context.trace_id:032x}', case['trace_id'])
                self.assertLessEqual(case['started_ns'], span.start_time)
                self.assertLessEqual(span.end_time, case['finished_ns'])

    def test_decision_logs_are_created_from_branch_results(self):
        cases = self.run_requests()
        events = [json.loads(call.args[0]) for call in self.logger.info.call_args_list]
        self.assertEqual(len(events), 3)
        for event, case in zip(events, cases):
            for key in ('request_id', 'trace_id', 'decision', 'stop_stage'):
                self.assertEqual(event[key], case[key])
        self.assertNotIn('text', json.dumps(events))

    def test_sdk_observations_satisfy_analysis_contract(self):
        cases = self.run_requests()
        bundle = {'logs': [json.loads(call.args[0]) for call in self.logger.info.call_args_list],
                  'spans': [], 'closures': cases, 'downstream_calls': self.store.calls}
        for span in self.exporter.get_finished_spans():
            if span.name != 'security.request':
                bundle['spans'].append({'request_id': span.attributes['request_id'],
                    'trace_id': f'{span.context.trace_id:032x}', 'stage': span.name,
                    'sequence': span.attributes['sequence']})
        for case in cases:
            analysis = results.expected_analysis(bundle, case['request_id'])
            self.assertEqual(analysis['stop_stage'], case['stop_stage'])
            self.assertEqual(analysis['downstream_count'], case['downstream_count'])

    def test_provider_error_does_not_become_closed_success(self):
        self.store.lookup = Mock(side_effect=RuntimeError('provider unavailable'))
        with self.assertRaises(RuntimeError):
            workflow.handle_request('reader', 'notice_lookup', self.tracer, self.logger, self.store)
        self.logger.info.assert_not_called()


if __name__ == '__main__':
    unittest.main()
