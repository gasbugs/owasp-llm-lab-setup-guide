"""P19 HTTP execution contract, real child execution, SDK spans; mocked storage."""
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import logging
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

from fastapi.testclient import TestClient
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

ROOT = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-labs/h19-incident-investigation'
with patch.dict(sys.modules):
    for name in ('analysis_inputs', 'collection', 'execution', 'workflow', 'p19_server'):
        path = ROOT / ('server.py' if name == 'p19_server' else name + '.py')
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
server = module


class P19ServerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        self.source = self.state / 'investigation.py'
        self.source.write_text('def analyze_incident(bundle, request_id):\n return {"request_id": request_id}\n')
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        logger = Mock(spec=logging.Logger)
        self.signals = SimpleNamespace(tracer=provider.get_tracer('p19'), logger=logger,
                                       flush=Mock(return_value=True), close=provider.shutdown)
        self.client = TestClient(server.create_app('control', 'verify', self.state, self.source, self.signals))
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        def collect(cases, calls):
            spans = [{'request_id': span.attributes['request_id'], 'trace_id': f'{span.context.trace_id:032x}',
                      'sequence': span.attributes['sequence'], 'stage': span.name}
                     for span in exporter.get_finished_spans() if span.name != 'security.request']
            return {'products': [], 'bundle': {'logs': [json.loads(call.args[0]) for call in logger.info.call_args_list],
                    'spans': spans, 'closures': cases, 'downstream_calls': calls}}
        patcher = patch.object(server.collection, 'collect', side_effect=collect)
        self.collect = patcher.start()
        self.addCleanup(patcher.stop)
        self.body = {'suite_id': str(uuid.uuid4()), 'started_at': datetime.now(timezone.utc).isoformat()}

    def run_suite(self):
        response = self.client.post('/v1/run/H19', headers={'Authorization': 'Bearer control'}, json=self.body)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_actual_function_runs_for_ten_server_owned_inputs(self):
        receipt = self.run_suite()
        self.assertEqual(receipt['activity_id'], 'P19')
        executions = receipt['analysis_executions']
        self.assertEqual(len(executions), 10)
        self.assertEqual(len({row['case_id'] for row in executions}), 10)
        self.assertEqual(sum(row['expected_invalid'] for row in executions), 4)
        self.assertTrue(all(row['execution_status'] == 'returned' for row in executions))
        self.assertTrue(all(row['value']['request_id'] == row['request_id'] for row in executions))
        self.assertTrue(all(row['source_digest'] == hashlib.sha256(self.source.read_bytes()).hexdigest()
                            for row in executions))
        self.assertNotIn('task_completed', receipt)
        self.assertNotIn('course_verdict', receipt)
        self.assertEqual(self.collect.call_count, 1)
        self.assertEqual(len(receipt['bundle']['downstream_calls']), 1)

    def test_auth_roles_and_browser_owned_grading_fields_are_rejected(self):
        for credential in ('', 'verify'):
            response = self.client.post('/v1/run/H19', headers={'Authorization': 'Bearer ' + credential}, json=self.body)
            self.assertEqual(response.status_code, 401)
        response = self.client.post('/v1/run/H19', headers={'Authorization': 'Bearer control'},
                                    json={**self.body, 'task_completed': True})
        self.assertEqual(response.status_code, 422)
        self.collect.assert_not_called()
        self.assertEqual(self.client.get('/v1/h19/build-info', headers={'Authorization': 'Bearer control'}).status_code, 401)

    def test_duplicate_suite_cannot_replay_requests_and_receipt_is_readonly(self):
        receipt = self.run_suite()
        response = self.client.post('/v1/run/H19', headers={'Authorization': 'Bearer control'}, json=self.body)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.collect.call_count, 1)
        path = '/v1/receipts/H19/' + self.body['suite_id']
        self.assertEqual(self.client.get(path, headers={'Authorization': 'Bearer verify'}).json(), receipt)
        self.assertEqual(self.client.get(path, headers={'Authorization': 'Bearer control'}).status_code, 401)
        self.assertEqual(self.client.get('/v1/h19/ledger/' + self.body['suite_id'],
                                        headers={'Authorization': 'Bearer verify'}).json()['closed'], True)

    def test_storage_failure_does_not_turn_into_negative_analysis_case(self):
        self.collect.side_effect = TimeoutError('storage unavailable')
        receipt = self.run_suite()
        self.assertEqual(receipt['execution_error'], 'TimeoutError')
        self.assertEqual(receipt['analysis_executions'], [])
        self.assertNotIn('bundle', receipt)
        self.assertEqual(len(receipt['cases']), 3)

    def test_broken_learner_does_not_break_service_readiness(self):
        self.source.write_text('not valid Python!')
        self.assertEqual(self.client.get('/readyz').status_code, 200)
        receipt = self.run_suite()
        self.assertTrue(all(row['execution_status'] == 'runtime_error' for row in receipt['analysis_executions']))
        self.assertEqual(self.client.get('/readyz').status_code, 200)

    def test_stale_or_invalid_metadata_never_starts_work(self):
        for extra in ({'suite_id': '../../foreign'},
                      {'started_at': (datetime.now(timezone.utc) - timedelta(minutes=4)).isoformat()},
                      {'started_at': 'not-a-time'}):
            response = self.client.post('/v1/run/H19', headers={'Authorization': 'Bearer control'}, json={**self.body, **extra})
            self.assertEqual(response.status_code, 422)
        self.collect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
