"""P12 UI orchestration: server-owned IDs and bounded, non-retrying transport."""
import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch
from uuid import UUID

import httpx
from fastapi.testclient import TestClient
from test_guided_control_center import load_server


class P12ControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server()

    def setUp(self):
        self.client = TestClient(self.server.app)
        self.client.get('/')
        bootstrap = self.client.get('/api/bootstrap').json()
        self.headers = {'Origin': 'http://testserver', 'X-CSRF-Token': bootstrap['csrf_token']}
        self.calls = []
        self.mutate = lambda result: None
        self.run_state = 'finished'

    async def receive(self, client, url, token, suite, deadline):
        self.calls.append((url, token, suite, deadline))
        UUID(suite)
        if url.endswith('/v1/run'):
            return {'suite_id': suite, 'run_state': self.run_state}
        result = {'activity_id': 'P12', 'execution_id': suite, 'contract_version': 2,
                  'verified_by': 'guided-evidence-verifier', 'task_completed': True,
                  'security_verdict': 'PASS', 'course_verdict': 'PASS',
                  'result': {'practice_id': 'P12', 'execution_id': 'H12', 'suite_id': suite,
                             'contract_version': 2, 'task_completed': True, 'security_verdict': 'PASS'}}
        self.mutate(result)
        return result

    def post(self, **kwargs):
        return self.client.post('/api/practice/P12/verify', headers=self.headers, **kwargs)

    def test_actual_routes_only_and_fresh_suite_per_request(self):
        with patch.object(self.server, 'p12_post_json', side_effect=self.receive):
            self.assertTrue(self.post().json()['task_completed'])
            self.assertTrue(self.post().json()['task_completed'])
        self.assertEqual([c[0] for c in self.calls[:2]],
                         [self.server.LAB12_URL + '/v1/run', self.server.VERIFIER_URL + '/v1/verify/p12'])
        self.assertEqual(self.calls[0][2], self.calls[1][2])
        self.assertNotEqual(self.calls[0][2], self.calls[2][2])
        self.assertEqual([c[1] for c in self.calls[:2]], [self.server.LAB12_TOKEN, self.server.VERIFIER_TOKEN])
        self.assertFalse(self.server.ACTIVE_SESSIONS)

    def test_no_browser_verdict_or_suite(self):
        with patch.object(self.server, 'p12_post_json', new_callable=AsyncMock) as downstream:
            for body in ({'task_completed': True}, {'suite_id': 'browser-owned'}, {}):
                self.assertEqual(self.post(json=body).status_code, 422)
            downstream.assert_not_called()

    def test_missing_session_and_csrf_are_rejected(self):
        self.assertEqual(TestClient(self.server.app).post('/api/practice/P12/verify').status_code, 401)
        self.assertEqual(self.client.post('/api/practice/P12/verify').status_code, 403)

    def test_invalid_verifier_identity_and_outcomes(self):
        for key, value in [('activity_id', 'H12'), ('execution_id', 'stale'),
                           ('contract_version', True), ('task_completed', 1),
                           ('course_verdict', 'ERR'), ('result', []), ('verified_by', 'learner')]:
            with self.subTest(key=key):
                self.mutate = lambda result, key=key, value=value: result.update({key: value})
                with patch.object(self.server, 'p12_post_json', side_effect=self.receive):
                    result = self.post().json()
                self.assertFalse(result['task_completed'])
                self.assertEqual(result['security_verdict'], 'ERR')
                self.assertIsNone(result['downstream_called'])
                self.assertFalse(self.server.ACTIVE_SESSIONS)

    def test_runner_error_still_asks_independent_verifier_but_cannot_complete(self):
        self.run_state = 'error'
        with patch.object(self.server, 'p12_post_json', side_effect=self.receive):
            result = self.post().json()
        self.assertEqual(len(self.calls), 2)
        self.assertFalse(result['task_completed'])

    def test_verifier_incomplete_is_preserved(self):
        def incomplete(result):
            result.update(task_completed=False, security_verdict='ERR', course_verdict='ERR')
            result['result'].update(task_completed=False, security_verdict='ERR')
        self.mutate = incomplete
        with patch.object(self.server, 'p12_post_json', side_effect=self.receive):
            result = self.post().json()
        self.assertFalse(result['task_completed'])
        self.assertIn('result', result)

    def test_transport_failure_does_not_claim_zero_calls_and_unlocks(self):
        for error in (httpx.ConnectError('hidden-token'), TimeoutError('hidden-token'), ValueError('hidden-token')):
            with patch.object(self.server, 'p12_post_json', side_effect=error):
                response = self.post()
            self.assertNotIn('hidden-token', response.text)
            self.assertIsNone(response.json()['downstream_called'])
            self.assertFalse(self.server.ACTIVE_SESSIONS)

    def test_real_client_body_no_redirects_and_response_bounds(self):
        async def run():
            requests = []
            def handler(request):
                requests.append(request)
                self.assertEqual(json.loads(request.content), {'suite_id': 'test-suite'})
                self.assertEqual(request.headers['authorization'], 'Bearer test-token')
                return httpx.Response(200, json={'suite_id': 'test-suite'})
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                        trust_env=False, follow_redirects=False) as client:
                self.assertEqual(await self.server.p12_post_json(client, 'http://runner/v1/run',
                                 'test-token', 'test-suite', 1), {'suite_id': 'test-suite'})
            self.assertEqual(len(requests), 1)
            for response in (httpx.Response(302, headers={'location': 'http://other'}),
                             httpx.Response(503), httpx.Response(200, content=b'x' * 2097153),
                             httpx.Response(200, content=b'[]'), httpx.Response(200, content=b'invalid')):
                async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: response),
                                            trust_env=False, follow_redirects=False) as client:
                    with self.assertRaises(ValueError):
                        await self.server.p12_post_json(client, 'http://runner/v1/run', 'token', 'suite', 1)
        asyncio.run(run())


if __name__ == '__main__':
    unittest.main()
