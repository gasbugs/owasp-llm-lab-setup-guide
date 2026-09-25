"""P17 HTTP authentication, identity, failed workers and real child isolation."""
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
import uuid

from fastapi.testclient import TestClient

BASE = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-labs/h17-telemetry'
spec = importlib.util.spec_from_file_location('p17_server', BASE / 'server.py')
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class P17ServerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name)
        self.source = self.state / 'source.py'
        self.source.write_text((BASE / 'instrumentation.py').read_text())
        self.executor = Mock(return_value={'closed': False, 'execution_error': 'worker_timeout'})
        self.client = TestClient(server.create_app('control', 'verify', self.state,
                                                  self.source, self.executor, sampler=lambda stamp: stamp))
        self.body = {'suite_id': str(uuid.uuid4()), 'started_at': datetime.now(timezone.utc).isoformat()}
        self.headers = {'Authorization': 'Bearer control'}

    def test_auth_and_grading_submission_are_rejected(self):
        self.assertEqual(self.client.post('/v1/run/H17', json=self.body).status_code, 401)
        self.assertEqual(self.client.post('/v1/run/H17', headers=self.headers,
            json={**self.body, 'task_completed': True}).status_code, 422)
        self.executor.assert_not_called()

    def test_unfinished_worker_is_saved_without_claiming_zero_calls_or_pass(self):
        response = self.client.post('/v1/run/H17', headers=self.headers, json=self.body)
        self.assertEqual(response.status_code, 200)
        value = response.json()
        self.assertFalse(value['execution']['closed'])
        self.assertNotIn('task_completed', value)
        self.assertNotIn('downstream_count', value['execution'])
        path = '/v1/h17/ledger/' + self.body['suite_id']
        self.assertEqual(self.client.get(path).status_code, 401)
        self.assertFalse(self.client.get(path, headers={'Authorization': 'Bearer verify'}).json()['closed'])
        self.assertEqual(self.client.post('/v1/run/H17', headers=self.headers, json=self.body).status_code, 409)
        self.executor.assert_called_once()

    def test_invalid_and_stale_metadata_never_execute(self):
        for body in ({**self.body, 'suite_id': '../escape'},
                     {**self.body, 'started_at': '2020-01-01T00:00:00+00:00'},
                     {**self.body, 'started_at': '2026-01-01T00:00:00'}):
            self.assertEqual(self.client.post('/v1/run/H17', headers=self.headers, json=body).status_code, 422)
        self.executor.assert_not_called()

    def test_ready_does_not_import_broken_learner(self):
        self.source.write_text('def broken(:')
        self.assertEqual(self.client.get('/readyz').status_code, 200)
        self.executor.assert_not_called()

    def test_real_worker_starter_and_timeout(self):
        value = server.execute(self.source, {'allow': 0, 'block': 0})
        self.assertEqual([c['execution_status'] for c in value['cases']], ['not_implemented'] * 3)
        self.source.write_text('while True: pass\n')
        value = server.execute(self.source, {'allow': 0, 'block': 0}, timeout=0.5)
        self.assertEqual(value, {'closed': False, 'execution_error': 'worker_timeout'})


if __name__ == '__main__':
    unittest.main()
