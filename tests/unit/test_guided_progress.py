"""Completion persistence is server-owned and never a replacement for grading."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from test_guided_control_center import load_server


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.server = load_server()
        self.server.PROGRESS.db.close()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / 'progress.db')
        self.store = self.server.ProgressStore(self.path)
        self.addCleanup(self.store.db.close)
        self.server.PROGRESS = self.store
        self.client = TestClient(self.server.app)
        self.client.get('/')
        csrf = self.client.get('/api/bootstrap').json()['csrf_token']
        self.headers = {'Origin': 'http://testserver', 'X-CSRF-Token': csrf}

    def complete(self, problem='P01', **changes):
        payload = dict(activity_id=problem, execution_id='suite-1', task_completed=True,
                       course_verdict='PASS', verified_by='guided-evidence-verifier',
                       source_digest='a' * 64, result={})
        payload.update(changes)
        self.store.finish(problem, self.store.begin(problem), payload)

    def test_reopen_database_preserves_only_metadata(self):
        self.complete(prompt='secret-body', token='secret-token')
        reopened = self.server.ProgressStore(self.path)
        self.addCleanup(reopened.db.close)
        self.assertEqual(reopened.history(), self.store.history())
        self.assertNotIn('secret', str(reopened.history()))
        self.assertEqual(len(reopened.history()), 1)

    def test_only_verified_completion_is_saved(self):
        for changes in ({'task_completed': False}, {'course_verdict': 'ERR'},
                        {'verified_by': 'browser'}, {'activity_id': 'P02'},
                        {'execution_id': ''}, {'resource_ready': True}):
            self.complete(**changes)
            self.assertEqual(self.store.history(), [])
        self.complete(course_verdict='HIT')
        self.assertEqual(len(self.store.history()), 1)

    def test_failed_new_attempt_retains_history_but_requires_recheck(self):
        self.complete()
        self.store.begin('P01')
        self.assertEqual(self.store.history()[0]['needs_check'], 1)
        self.assertEqual(self.store.history()[0]['execution'], 'suite-1')

    def test_older_parallel_success_cannot_override_new_attempt(self):
        old = self.store.begin('P01')
        self.store.begin('P01')
        self.store.finish('P01', old, dict(activity_id='P01', execution_id='old',
                          task_completed=True, course_verdict='PASS', verified_by='guided-evidence-verifier'))
        self.assertEqual(self.store.history(), [])

    def test_restore_changed_and_missing_build_are_distinct(self):
        import httpx
        digest = ['a' * 64]
        class Client:
            def __init__(self, **kwargs): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *args): pass
            async def get(self, url, headers):
                return httpx.Response(200, json={'source_digest': digest[0]})
        self.complete()
        with patch.object(self.server.httpx, 'AsyncClient', Client):
            self.assertEqual(self.client.get('/api/progress').json()['records'][0]['state'], 'completed')
            digest[0] = None
            self.assertEqual(self.client.get('/api/progress').json()['records'][0]['state'], 'recheck')
            digest[0] = 'b' * 64
            record = self.client.get('/api/progress').json()['records'][0]
            self.assertEqual(record['state'], 'recheck')
            self.assertIn('바뀌', record['reason'])
            digest[0] = 'a' * 64
            self.assertEqual(self.client.get('/api/progress').json()['records'][0]['state'], 'recheck')

    def test_browser_cannot_write_progress_or_invalidate_without_csrf(self):
        self.complete()
        self.assertEqual(TestClient(self.server.app).get('/api/progress').status_code, 401)
        self.assertEqual(self.client.post('/api/progress', json={'task_completed': True}, headers=self.headers).status_code, 405)
        self.assertEqual(self.client.post('/api/practice/P01/verify').status_code, 403)
        self.assertEqual(self.store.history()[0]['needs_check'], 0)
        self.assertEqual(self.client.post('/api/practice/P01/verify', json={'task_completed': True}, headers=self.headers).status_code, 422)
        self.assertEqual(self.store.history()[0]['needs_check'], 0)

    def test_valid_http_result_is_persisted_by_middleware(self):
        async def run(_session, _mode):
            return dict(activity_id='P01', execution_id='suite-http', task_completed=True,
                        course_verdict='PASS', verified_by='guided-evidence-verifier', source_digest='a' * 64)
        # Replace only the transport-heavy suite; the public route/auth/middleware remain real.
        with patch.object(self.server, 'execute_suite', run):
            response = self.client.post('/api/practice/P01/verify', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.store.history()[0]['execution'], 'suite-http')
