"""Real policy branches, OTEL spans and counters; no external services."""
import importlib.util
import json
import logging
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid
import httpx
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from prometheus_client import Counter, CollectorRegistry

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs"
with patch.dict(sys.modules):
    for name, path in (("query_execution", ROOT / "observability/query_execution.py"),
                       ("p18_workflow", ROOT / "h18-product-queries/request_workflow.py")):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
workflow = module


class P18WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.exporter = InMemorySpanExporter()
        self.provider = TracerProvider()
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.addCleanup(self.provider.shutdown)
        self.tracer = self.provider.get_tracer("p18-test")
        self.registry = CollectorRegistry()
        self.counter = Counter("guided_security_decisions_total", "decisions", ["hands_on", "decision"], registry=self.registry)
        self.logger = Mock(spec=logging.Logger)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.query = self.state / "queries.yaml"
        self.query.write_text("logql: '{}'\npromql: 'up'\ntrace_lookup: exact_trace_id\n")
        scrape = patch.object(workflow, 'wait_for_scrape')
        self.scrape = scrape.start()
        self.addCleanup(scrape.stop)

    def action(self, action, principal, store):
        return workflow.handle_action(action, principal, self.tracer, self.logger, self.counter, store)

    def test_decision_and_downstream_follow_actual_authorization(self):
        store = workflow.NoticeStore()
        normal = self.action("notice_lookup", "reader", store)
        denied = self.action("notice_publish", "reader", store)
        self.assertEqual([normal["decision"], denied["decision"]], ["allow", "block"])
        self.assertTrue(normal["downstream_called"])
        self.assertFalse(denied["downstream_called"])
        self.assertEqual(len(store.calls), 1)
        self.assertEqual(store.calls[0]["request_id"], normal["request_id"])
        self.assertEqual(store.calls[0]["trace_id"], normal["trace_id"])
        self.assertEqual(normal["result"]["notice_id"], "training-notice")
        self.assertIsNone(denied["result"])
        for decision in ("allow", "block"):
            self.assertEqual(self.registry.get_sample_value("guided_security_decisions_total", {"hands_on": "H18", "decision": decision}), 1)
        events = [call.kwargs["extra"] for call in self.logger.info.call_args_list]
        self.assertEqual([e["decision"] for e in events], ["allow", "block"])
        for event, case in zip(events, (normal, denied)):
            self.assertEqual(event["request_id"], case["request_id"])
            self.assertEqual(event["trace_id"], case["trace_id"])

    def test_spans_link_decision_and_actual_downstream(self):
        store = workflow.NoticeStore()
        normal = self.action("notice_lookup", "reader", store)
        denied = self.action("notice_publish", "reader", store)
        spans = self.exporter.get_finished_spans()
        for case, names in ((normal, {"security.request", "authorize", "notice_lookup"}),
                            (denied, {"security.request", "authorize"})):
            own = [s for s in spans if f"{s.context.trace_id:032x}" == case["trace_id"]]
            self.assertEqual({s.name for s in own}, names)
            root = next(s for s in own if s.parent is None)
            self.assertEqual(root.attributes["decision"], case["decision"])
            for child in own:
                if child.parent:
                    self.assertEqual(child.parent.span_id, root.context.span_id)
        for metric in self.registry.collect():
            for sample in metric.samples:
                self.assertNotIn("request_id", sample.labels)
                self.assertNotIn("trace_id", sample.labels)

    def test_unknown_principal_or_action_is_denied(self):
        store = workflow.NoticeStore()
        for action, principal in (("notice_lookup", "unknown"), ("unknown", "reader")):
            self.assertEqual(self.action(action, principal, store)["decision"], "block")
        self.assertEqual(store.calls, [])

    def suite(self, body):
        return workflow.run_suite(body, self.query, self.tracer, self.logger, self.counter,
                                  self.provider, Mock(), self.state)

    def test_suite_records_closed_execution_and_executes_both_queries(self):
        body = {"suite_id": str(uuid.uuid4()), "started_at": "2026-09-24T00:00:00+00:00"}
        available = {'products': {'loki': {'response': {'data': {'result': ['log']}}},
                                  'tempo': {'response': {'batches': ['trace']}}}}
        with patch.object(workflow, "execute_queries", return_value=available) as query:
            result = self.suite(body)
        self.assertEqual(query.call_count, 2)
        ledger = json.loads((self.state / f'H18-{body["suite_id"]}-ledger.json').read_text())
        self.assertTrue(ledger["closed"])
        self.assertEqual(len(ledger["downstream_calls"]), 1)
        self.assertEqual([c["decision"] for c in result["cases"]], ["allow", "block"])
        for call, case in zip(query.call_args_list, result["cases"]):
            self.assertEqual(call.args[1:3], (case["request_id"], case["trace_id"]))
        self.assertEqual(result["provider_mode"], "synthetic-notice-store")
        self.assertNotIn("task_completed", result)
        with self.assertRaises(FileExistsError):
            self.suite(body)

    def test_malformed_queries_leave_execution_but_no_query_success(self):
        self.query.write_text("[invalid: [")
        body = {"suite_id": str(uuid.uuid4()), "started_at": "2026-09-24T00:00:00+00:00"}
        result = self.suite(body)
        self.assertIn("query_error", result)
        self.assertNotIn("query_execution", result)
        self.assertEqual(len(result["cases"]), 2)


class P18CollectionTests(unittest.TestCase):
    def test_waits_for_both_current_scrapes(self):
        def response(stamp):
            return httpx.Response(200, request=httpx.Request('GET', 'http://prometheus'), json={
                'data': {'result': [{'metric': {'decision': d}, 'value': [20, str(stamp)]}
                                    for d in ('allow', 'block')]}})
        client = Mock()
        client.get.side_effect = [response(5), response(11)]
        with patch.object(workflow.time, 'sleep'):
            workflow.wait_for_scrape(10_000_000_000, client=client)
        self.assertEqual(client.get.call_count, 2)
        client.close.assert_not_called()

    def test_scrape_timeout_is_not_success(self):
        client = Mock()
        client.get.return_value = httpx.Response(200, request=httpx.Request('GET', 'http://prometheus'),
                                                json={'data': {'result': []}})
        with self.assertRaises(TimeoutError):
            workflow.wait_for_scrape(1, client=client, timeout=0)

    def test_trace_export_pending_retries_queries_not_actions(self):
        missing = httpx.Response(404, request=httpx.Request('GET', 'http://tempo/api/traces/id'))
        ready = {'products': {'loki': {'response': {'data': {'result': ['log']}}},
                               'tempo': {'response': {'batches': ['trace']}}}}
        query = {'logql': 'learner', 'promql': 'learner', 'trace_lookup': 'exact_trace_id'}
        cases = [{'request_id': 'one', 'trace_id': 'trace-one'},
                 {'request_id': 'two', 'trace_id': 'trace-two'}]
        error = httpx.HTTPStatusError('pending', request=missing.request, response=missing)
        with patch.object(workflow, 'execute_queries', side_effect=[error, ready, ready]) as execute, \
                patch.object(workflow.time, 'sleep'):
            self.assertEqual(len(workflow.collected_queries(query, cases, 1)), 2)
        self.assertEqual([call.args[1] for call in execute.call_args_list], ['one', 'one', 'two'])
        self.assertTrue(all(call.args[0] is query for call in execute.call_args_list))

    def test_invalid_query_is_not_retried(self):
        response = httpx.Response(400, request=httpx.Request('GET', 'http://loki'))
        error = httpx.HTTPStatusError('invalid', request=response.request, response=response)
        with patch.object(workflow, 'execute_queries', side_effect=error) as execute:
            with self.assertRaises(httpx.HTTPStatusError):
                workflow.collected_queries({}, [{'request_id': 'one', 'trace_id': 'trace'}], 1)
        self.assertEqual(execute.call_count, 1)

    def test_missing_log_times_out_without_completing(self):
        empty = {'products': {'loki': {'response': {'data': {'result': []}}},
                               'tempo': {'response': {'batches': ['trace']}}}}
        with patch.object(workflow, 'execute_queries', return_value=empty):
            with self.assertRaises(TimeoutError):
                workflow.collected_queries({}, [{'request_id': 'one', 'trace_id': 'trace'}], 1, timeout=0)


if __name__ == "__main__":
    unittest.main()
