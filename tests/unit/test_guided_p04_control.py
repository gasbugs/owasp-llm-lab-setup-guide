"""P04 browser orchestration must not reuse the old H04 four-request exercise."""
import json
import unittest
from unittest.mock import patch
from uuid import UUID

import httpx
from fastapi.testclient import TestClient
from test_guided_control_center import load_server


class P04ControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server()

    def setUp(self):
        self.client = TestClient(self.server.app)
        self.client.get('/')
        self.bootstrap = self.client.get('/api/bootstrap').json()
        self.headers = {'Origin': 'http://testserver', 'X-CSRF-Token': self.bootstrap['csrf_token']}
        self.calls = []
        self.change = lambda path, value: value
        original = httpx.AsyncClient
        self.factory = lambda **kw: original(transport=httpx.MockTransport(self.receive), **kw)

    def receive(self, request):
        body = json.loads(request.content)
        self.calls.append((request.url.path, body, request.headers['authorization']))
        if request.url.path.endswith('/resources/prepare'):
            value = {'practice_id': 'P04', 'operation_id': body['operation_id'], 'state': 'ready',
                     'resources': {'provider_mode': 'aws'}, 'evidence': {}}
        elif request.url.path == '/v1/chat':
            value = {'practice_id':'P04', 'graded':False, 'message':body['message'], 'execution':{}}
        elif request.url.path == '/v1/start':
            value = {'suite_id':body['suite_id'],'started_at':1000,'cases':[{'case_id':f'case-{i}'} for i in range(27)]}
        elif request.url.path == '/v1/step':
            value = {**body,'case_id':f"case-{body['index']}"}
        elif request.url.path == '/v1/finish':
            value = {'suite_id':body['suite_id'],'run_state':'error' if body['stopped'] else 'finished'}
        elif request.url.path == '/v1/verify/p04-case':
            value = {**body,'case_id':f"case-{body['index']}",'status':'PASS','case_verified':True}
        else:
            self.assertEqual(request.url.path, '/v1/verify/p04')
            value = {'activity_id': 'P04', 'execution_id': body['suite_id'],
                     'contract_version': 'p04-guardrail-v1', 'verified_by': 'guided-evidence-verifier',
                     'task_completed': True, 'security_verdict': 'PASS', 'course_verdict': 'PASS',
                     'result': {'provider_mode': 'contract', 'source_digest': 'a' * 64},
                     'reason': 'synthetic contract only'}
        return httpx.Response(200, json=self.change(request.url.path, value))

    def post(self, action='verify', **kwargs):
        with patch.object(self.server.httpx, 'AsyncClient', side_effect=self.factory):
            return self.client.post('/api/practice/P04/' + action, headers=self.headers, **kwargs)

    def test_custom_chat_does_not_grade_or_accept_client_policy(self):
        response = self.post('chat', json={'message':'이메일을 확인해 주세요.'})
        self.assertEqual(response.status_code,200)
        self.assertFalse(response.json()['graded'])
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0][0],'/v1/chat')
        self.assertEqual(self.calls[0][1],{'message':'이메일을 확인해 주세요.'})
        self.assertEqual(self.post('chat',json={'message':'문장','guardrailIdentifier':'spoof'}).status_code,422)
        self.assertEqual(self.client.post('/api/practice/P04/chat',json={'message':'문장'}).status_code,403)

    def test_fresh_suite_and_role_separation_with_raw_result_preserved(self):
        for _ in range(2):
            result = self.post()
            self.assertEqual(result.status_code, 200)
            self.assertTrue(result.json()['task_completed'])
            self.assertEqual(result.json()['result']['provider_mode'], 'contract')
        starts=[call for call in self.calls if call[0]=='/v1/start']
        self.assertEqual(len(starts),2)
        self.assertNotEqual(starts[0][1],starts[1][1])
        self.assertEqual(starts[0][2],'Bearer '+self.server.LAB04_TOKEN)
        for index,call in enumerate(self.calls[:54]):
            if index:
                self.assertEqual(call[0],'/v1/step' if index%2 else '/v1/verify/p04-case')
        self.assertEqual(sum(call[0]=='/v1/step' for call in self.calls),54)
        self.assertFalse(self.server.ACTIVE_SESSIONS)

    def test_first_case_failure_stops_remaining_calls_and_keeps_progress(self):
        self.change=lambda path,row: {**row,'status':'ERR','case_verified':False} if path=='/v1/verify/p04-case' else row
        result=self.post().json()
        self.assertFalse(result['task_completed'])
        self.assertEqual(result['security_verdict'],'ERR')
        self.assertEqual(sum(call[0]=='/v1/step' for call in self.calls),1)
        self.assertEqual([call[0] for call in self.calls],['/v1/start','/v1/step','/v1/verify/p04-case','/v1/finish'])
        self.assertTrue(self.calls[-1][1]['stopped'])
        self.assertEqual(result['result']['cases'][0]['status'],'ERR')
        self.assertEqual(sum(row['status']=='미실행' for row in result['result']['cases']),26)
        progress=self.client.get('/api/test-progress/P04').json()
        self.assertEqual(progress['phase'],'finished')
        self.assertEqual(len(progress['cases']),1)
        self.assertIsNone(progress['current_case'])

    def test_browser_fields_and_missing_auth_are_rejected_before_downstream(self):
        for action in ('verify', 'provision'):
            for body in ({}, {'suite_id': 'caller'}, {'task_completed': True}, {'guardrailIdentifier': 'caller'}):
                self.assertEqual(self.post(action, json=body).status_code, 422)
            self.assertEqual(TestClient(self.server.app).post('/api/practice/P04/' + action).status_code, 401)
            self.assertEqual(self.client.post('/api/practice/P04/' + action).status_code, 403)
        self.assertEqual(self.calls, [])

    def test_wrong_current_verifier_identity_or_verdict_is_err(self):
        for field, value in (('activity_id', 'H04'), ('execution_id', 'stale'),
                             ('contract_version', 'old'), ('verified_by', 'learner'),
                             ('task_completed', 1), ('security_verdict', 'HIT'),
                             ('course_verdict', 'ERR')):
            with self.subTest(field=field):
                self.change = lambda path, row: {**row, field: value} if path.endswith('/verify/p04') else row
                result = self.post()
                self.assertEqual(result.status_code, 502)
                self.assertFalse(result.json()['detail']['task_completed'])
                self.assertEqual(result.json()['detail']['security_verdict'], 'ERR')
                self.assertFalse(self.server.ACTIVE_SESSIONS)

    def test_runner_wrong_suite_stops_before_grading(self):
        self.change = lambda path, row: {**row, 'suite_id': 'stale'} if path == '/v1/start' else row
        self.assertEqual(self.post().status_code, 502)
        self.assertFalse(any(call[0] == "/v1/step" for call in self.calls))
        self.assertFalse(self.server.ACTIVE_SESSIONS)

    def test_incomplete_after_success_is_not_cached(self):
        self.assertTrue(self.post().json()['task_completed'])
        self.change = lambda path, row: {**row, 'task_completed': False, 'security_verdict': 'ERR',
                                        'course_verdict': 'ERR'} if path.endswith('/verify/p04') else row
        result = self.post().json()
        self.assertFalse(result['task_completed'])
        self.assertEqual(result['security_verdict'], 'ERR')

    def test_preparation_has_no_course_verdict_and_uses_p04_namespace(self):
        result = self.post('provision')
        self.assertEqual(result.status_code, 200)
        self.assertFalse(result.json()['task_completed'])
        self.assertTrue(result.json()['resource_ready'])
        self.assertNotIn('security_verdict', result.json())
        self.assertEqual(self.calls[0][0], '/v1/p04/resources/prepare')
        self.assertEqual(set(self.calls[0][1]), {'operation_id'})
        self.assertEqual(self.calls[0][2], 'Bearer ' + self.server.H04_PROVISION_TOKEN)

    def test_invalid_preparation_is_not_ready(self):
        for field, value in (('practice_id', 'H04'), ('operation_id', 'stale'), ('state', 'pending'),
                             ('resources', {'provider_mode': 'contract'}), ('evidence', None)):
            with self.subTest(field=field):
                self.change = lambda path, row: {**row, field: value}
                result = self.post('provision')
                self.assertEqual(result.status_code, 502)
                self.assertFalse(result.json()['detail']['task_completed'])
                self.assertFalse(self.server.ACTIVE_SESSIONS)

    def test_transport_failure_does_not_claim_no_calls_and_releases_session(self):
        def fail(path, row):
            raise httpx.ReadTimeout('private provider detail')
        self.change = fail
        result = self.post()
        self.assertEqual(result.status_code, 502)
        self.assertIn('중단', result.json()['detail']['reason'])
        self.assertNotIn('private provider detail', result.text)
        self.assertFalse(self.server.ACTIVE_SESSIONS)
        self.assertEqual(self.client.get('/readyz').status_code, 200)

    def test_problem_surface_exposes_contract_not_answer_toggle(self):
        app = next(row for row in self.bootstrap['learner_apps'] if row['practice_id'] == 'P04')
        self.assertTrue(app['source_path'].endswith('/h04-bedrock-guardrail/learner.py'))
        html = self.client.get('/').text.split('id="h04-work"', 1)[1].split('id="h05-work"', 1)[0]
        for text in ('invoke_guarded(body, guardrail, services)', 'ValueError', '27개 사례', '1000', '원문'):
            self.assertIn(text, html)
        self.assertNotIn('USE_GUARDRAIL_FOR_CONVERSE', html)
        self.assertNotIn('/h04-bedrock-guardrail/server.py', html)
        self.assertNotIn('async def invoke_guarded', html)
