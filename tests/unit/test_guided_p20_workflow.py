"""Actual synthetic authorization, durable counters and credential separation."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

from fastapi.testclient import TestClient
import httpx
from prometheus_client import CollectorRegistry, generate_latest

ROOT = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-labs/h20-alert-dashboard'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


workflow = load('p20_workflow', 'workflow.py')
with patch.dict(sys.modules, {'workflow': workflow}):
    server = load('p20_server', 'server.py')


class P20WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = Path(self.temp.name) / 'state.sqlite3'
        self.app = workflow.Workflow(self.database)
        self.suite = str(uuid.uuid4())
        self.started = datetime.now(timezone.utc).isoformat()

    def phase(self, phase):
        if phase == 'normal':
            try:
                self.app.receipt(self.suite)
            except KeyError:
                self.app.run_phase(self.suite, self.started, 'prepare')
        return self.app.run_phase(self.suite, self.started, phase)

    def metrics(self, app=None):
        registry = CollectorRegistry()
        registry.register(app or self.app)
        return generate_latest(registry).decode()

    def test_only_authorized_notice_lookup_reaches_store(self):
        normal = self.phase('normal')
        self.assertEqual([r['downstream_count'] for r in normal['cases']], [1, 0, 0, 0])
        self.assertEqual([r['decision'] for r in normal['cases']], ['allow', 'block', 'block', 'block'])
        self.assertFalse(normal['closed'])
        self.phase('risk')
        final = self.phase('recovery')
        self.assertEqual([r['downstream_count'] for r in final['cases']], [1, 0, 0, 0, 0, 0, 1])
        self.assertTrue(final['requests_closed'])
        self.assertFalse(final['closed'])
        self.assertEqual(len({r['request_id'] for r in final['cases']}), 7)

    def test_metrics_are_committed_requests_not_a_toggle(self):
        self.phase('normal')
        self.assertIn('guided_p20_decisions_total{decision="allow",practice="P20"} 1.0', self.metrics())
        self.assertIn('guided_p20_decisions_total{decision="block",practice="P20"} 0.0', self.metrics())
        self.assertIn('guided_p20_decisions_total{decision="block",practice="background"} 3.0', self.metrics())
        self.assertNotIn('suite_id=', self.metrics())
        self.assertNotIn('request_id=', self.metrics())
        self.phase('risk')
        self.assertIn('guided_p20_decisions_total{decision="block",practice="P20"} 2.0', self.metrics())
        self.assertEqual(self.metrics(), self.metrics(workflow.Workflow(self.database)))

    def test_execution_build_is_durable_and_changed_config_blocks_next_phase(self):
        artifacts = Path(self.temp.name) / 'artifacts'
        artifacts.mkdir()
        for name in ('rules.yaml', 'dashboard.json'):
            shutil.copy2(ROOT / name, artifacts / name)
        self.app = workflow.Workflow(self.database, artifacts)
        first = self.phase('normal')
        self.assertEqual(first['build'], self.app.buildinfo())
        self.app = workflow.Workflow(self.database, artifacts)
        self.assertEqual(first, self.app.receipt(self.suite))
        original = (artifacts / 'rules.yaml').read_text()
        (artifacts / 'rules.yaml').write_text(original + '\n# harmless edit, but a different execution build\n')
        with self.assertRaises(workflow.Conflict):
            self.phase('risk')
        self.assertEqual(first, self.app.receipt(self.suite))
        (artifacts / 'rules.yaml').write_text(original)
        self.phase('risk')

    def test_missing_config_rolls_back_suite_creation(self):
        self.app = workflow.Workflow(self.database, self.temp.name)
        with self.assertRaises(FileNotFoundError):
            self.phase('normal')
        with self.assertRaises(KeyError):
            self.app.receipt(self.suite)

    def test_product_snapshots_persist_without_accepting_caller_content(self):
        observed = {'rules': {'native': 'before'}, 'dashboard': {'native': 'before'}}
        self.app = workflow.Workflow(self.database, observe_products=lambda: observed)
        prepared = self.phase('prepare')
        self.assertEqual(prepared['product_snapshots']['before']['body'], observed)
        self.recovered()
        self.onset = datetime.now(timezone.utc).isoformat()
        self.app.notification({'alerts': [self.alert('firing')]})
        self.app.notification({'alerts': [self.alert('resolved')]})
        observed['rules']['native'] = 'after'
        closed = self.app.close_observation(self.suite, self.started)
        self.assertEqual(closed['product_snapshots']['before']['body']['rules']['native'], 'before')
        self.assertEqual(closed['product_snapshots']['after']['body']['rules']['native'], 'after')
        self.assertEqual(workflow.Workflow(self.database).receipt(self.suite), closed)

    def test_product_collection_failure_does_not_create_or_close_execution(self):
        def unavailable():
            raise RuntimeError('product unavailable')
        self.app = workflow.Workflow(self.database, observe_products=unavailable)
        with self.assertRaises(RuntimeError):
            self.phase('prepare')
        with self.assertRaises(KeyError):
            self.app.receipt(self.suite)
        self.app.observe_products = lambda: {'rules': {}, 'dashboard': {}}
        self.recovered()
        self.onset = datetime.now(timezone.utc).isoformat()
        self.app.notification({'alerts': [self.alert('firing')]})
        self.app.notification({'alerts': [self.alert('resolved')]})
        self.app.observe_products = unavailable
        with self.assertRaises(RuntimeError):
            self.app.close_observation(self.suite, self.started)
        receipt = self.app.receipt(self.suite)
        self.assertFalse(receipt['closed'])
        self.assertEqual(set(receipt['product_snapshots']), {'before'})

    def test_native_collector_uses_fixed_read_only_urls_and_separate_auth(self):
        calls = []
        def transport(request):
            calls.append(request)
            return httpx.Response(200, json={'native': request.url.path})
        client = httpx.Client(transport=httpx.MockTransport(transport))
        self.addCleanup(client.close)
        with patch.object(server.httpx, 'Client', return_value=client):
            actual = server.product_observer('http://prometheus', 'http://grafana', ('reader', 'secret'))()
        self.assertEqual(set(actual), {'rules', 'dashboard'})
        self.assertEqual([r.method for r in calls], ['GET', 'GET'])
        self.assertEqual([r.url.path for r in calls], ['/api/v1/rules', '/api/dashboards/uid/guided-p20'])
        self.assertNotIn('Authorization', calls[0].headers)
        self.assertTrue(calls[1].headers['Authorization'].startswith('Basic '))

    def test_native_collector_failures_are_sanitized_and_do_not_return_partial_data(self):
        for fault in ('timeout', 'status', 'redirect', 'large', 'json'):
            def transport(request):
                if request.url.host == 'prometheus':
                    return httpx.Response(200, json={'status': 'success'})
                if fault == 'timeout': raise httpx.ReadTimeout('secret URL', request=request)
                if fault == 'status': return httpx.Response(503, text='secret details')
                if fault == 'redirect': return httpx.Response(302, headers={'location': 'http://elsewhere'})
                if fault == 'large': return httpx.Response(200, content=b'x' * 131073)
                return httpx.Response(200, content=b'invalid JSON')
            client = httpx.Client(transport=httpx.MockTransport(transport))
            self.addCleanup(client.close)
            with self.subTest(fault=fault):
                with patch.object(server.httpx, 'Client', return_value=client):
                    with self.assertRaises(server.HTTPException) as raised:
                        server.product_observer('http://prometheus', 'http://grafana', ('reader', 'secret'))()
                self.assertEqual(raised.exception.status_code, 503)
                self.assertEqual(raised.exception.detail, 'P20 product configuration unavailable')

    def test_checkpoints_use_server_clock_and_survive_reload_without_overwrite(self):
        prepared = self.phase('prepare')
        self.assertEqual(prepared['cases'], [])
        baseline = prepared['checkpoints']['baseline']
        self.phase('normal')
        clock = time.time_ns() + 9_000_000_000
        with patch.object(workflow.time, 'time_ns', return_value=clock):
            marked = self.app.mark_checkpoint(self.suite, self.started, 'normal')
        self.assertEqual(marked['checkpoints'], {'baseline': baseline, 'normal': clock // 1_000_000})
        self.app = workflow.Workflow(self.database)
        self.assertEqual(marked, self.app.receipt(self.suite))
        with self.assertRaises(workflow.Conflict):
            self.app.mark_checkpoint(self.suite, self.started, 'normal')
        with patch.object(workflow.time, 'time_ns', return_value=clock + 1_000_000_000):
            self.phase('risk')
            self.phase('recovery')
        with patch.object(workflow.time, 'time_ns', return_value=clock + 2_000_000_000):
            final = self.app.mark_checkpoint(self.suite, self.started, 'after_requests')
        self.assertEqual(final['checkpoints']['normal'], marked['checkpoints']['normal'])
        self.assertEqual(final['checkpoints']['after_requests'], (clock + 2_000_000_000) // 1_000_000)

    def test_early_foreign_and_wrong_phase_checkpoints_are_rejected(self):
        self.phase('prepare')
        with self.assertRaises(workflow.Conflict):
            self.app.mark_checkpoint(self.suite, self.started, 'normal')
        self.phase('normal')
        before = self.app.receipt(self.suite)
        for name in ('normal', 'after_requests'):
            with self.assertRaises(workflow.Conflict):
                self.app.mark_checkpoint(self.suite, self.started, name)
        with self.assertRaises(workflow.Conflict):
            self.app.mark_checkpoint(str(uuid.uuid4()), self.started, 'normal')
        with self.assertRaises(workflow.Conflict):
            self.app.mark_checkpoint(self.suite, datetime.now(timezone.utc).isoformat(), 'normal')
        self.assertEqual(before, self.app.receipt(self.suite))

    def recovered(self):
        for phase in ('normal', 'risk', 'recovery'):
            self.phase(phase)

    def alert(self, status, **changes):
        item = {'status': status, 'fingerprint': 'current-fingerprint',
                'labels': {'alertname': 'GuidedP20BlockedRequests', 'practice': 'P20', 'severity': 'warning'},
                'startsAt': self.onset, 'endsAt': datetime.now(timezone.utc).isoformat()}
        return {**item, **changes}

    def test_recovery_keeps_durable_lock_until_matching_notification_pair(self):
        self.recovered()
        self.app = workflow.Workflow(self.database)
        before = self.metrics()
        with self.assertRaises(workflow.Conflict):
            self.app.run_phase(str(uuid.uuid4()), self.started, 'normal')
        with self.assertRaises(workflow.Conflict):
            self.app.close_observation(self.suite, self.started)
        self.onset = datetime.now(timezone.utc).isoformat()
        self.app.notification({'alerts': [self.alert('firing')]})
        with self.assertRaises(workflow.Conflict):
            self.app.close_observation(self.suite, self.started)
        self.app.notification({'alerts': [self.alert('resolved')]})
        closed = self.app.close_observation(self.suite, self.started)
        self.assertTrue(closed['closed'])
        self.assertTrue(closed['requests_closed'])
        self.assertEqual(closed, self.app.close_observation(self.suite, self.started))
        self.assertEqual(before, self.metrics())
        next_suite, next_started = str(uuid.uuid4()), datetime.now(timezone.utc).isoformat()
        self.app.run_phase(next_suite, next_started, 'prepare')
        self.app.run_phase(next_suite, next_started, 'normal')
        self.assertEqual(closed, self.app.receipt(self.suite))

    def test_old_foreign_malformed_and_mismatched_notifications_do_not_close(self):
        self.recovered()
        self.onset = datetime.now(timezone.utc).isoformat()
        self.app.notification({'alerts': [self.alert('firing')]})
        for changes in ({'fingerprint': 'foreign'}, {'fingerprint': ''},
                        {'labels': {'practice': 'background'}},
                        {'startsAt': self.started}, {'endsAt': self.onset},
                        {'endsAt': datetime.now().isoformat()},
                        {'endsAt': (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}):
            self.app.notification({'alerts': [self.alert('resolved', **changes)]})
            with self.assertRaises(workflow.Conflict):
                self.app.close_observation(self.suite, self.started)
        self.app.notification({'alerts': [None, [], {'labels': 'bad'}]})
        self.app.notification({'alerts': 'bad'})
        with self.assertRaises(workflow.Conflict):
            self.app.close_observation(self.suite, self.started)
        with self.assertRaises(workflow.Conflict):
            self.app.close_observation(self.suite, datetime.now(timezone.utc).isoformat())

    def test_expired_observation_never_becomes_closed(self):
        self.recovered()
        with patch.object(workflow.time, 'time_ns', return_value=time.time_ns() + 181_000_000_000):
            with self.assertRaises(workflow.Conflict):
                self.app.close_observation(self.suite, self.started)
        self.assertFalse(self.app.receipt(self.suite)['closed'])

    def test_previous_alert_pair_and_reversed_delivery_cannot_release_current_suite(self):
        self.recovered()
        self.onset = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
        self.app.notification({'alerts': [self.alert('firing')]})
        self.app.notification({'alerts': [self.alert('resolved')]})
        with self.assertRaises(workflow.Conflict):
            self.app.close_observation(self.suite, self.started)
        self.onset = datetime.now(timezone.utc).isoformat()
        self.app.notification({'alerts': [self.alert('resolved')]})
        self.app.notification({'alerts': [self.alert('firing')]})
        with self.assertRaises(workflow.Conflict):
            self.app.close_observation(self.suite, self.started)

    def test_replay_skipped_phase_and_concurrent_suite_make_no_requests(self):
        with self.assertRaises(workflow.Conflict):
            self.app.run_phase(self.suite, self.started, 'normal')
        with self.assertRaises(workflow.Conflict):
            self.phase('risk')
        self.phase('normal')
        before = self.metrics()
        for phase in ('normal', 'recovery'):
            with self.assertRaises(workflow.Conflict):
                self.phase(phase)
        with self.assertRaises(workflow.Conflict):
            self.app.run_phase(str(uuid.uuid4()), self.started, 'normal')
        self.assertEqual(self.metrics(), before)

    def test_store_failure_rolls_back_request_and_count(self):
        with patch.object(self.app, 'lookup_notice', side_effect=RuntimeError('store unavailable')):
            with self.assertRaises(RuntimeError):
                self.phase('normal')
        receipt = self.app.receipt(self.suite)
        self.assertEqual(receipt['phase'], 'prepare')
        self.assertEqual(receipt['cases'], [])
        self.assertNotIn('} 1.0', self.metrics())

    def test_invalid_old_or_foreign_metadata_rejected(self):
        for suite, started in (('../path', self.started),
                               (self.suite, datetime.now().isoformat()),
                               (self.suite, (datetime.now(timezone.utc) - timedelta(minutes=4)).isoformat())):
            with self.assertRaises(ValueError):
                self.app.run_phase(suite, started, 'normal')
        self.phase('normal')
        with self.assertRaises(workflow.Conflict):
            self.app.run_phase(self.suite, datetime.now(timezone.utc).isoformat(), 'risk')

    def test_notifications_preserve_raw_content_and_time_window(self):
        start = time.time_ns()
        self.app.notification({'status': 'firing', 'alerts': [{'fingerprint': 'raw-product-value'}]})
        end = time.time_ns()
        saved = self.app.notifications(start, end)
        self.assertEqual(saved[0]['body']['alerts'][0]['fingerprint'], 'raw-product-value')
        self.assertEqual(self.app.notifications(end + 1, end + 2), [])
        with self.assertRaises(ValueError):
            self.app.notifications(0, 181_000_000_000)
        with self.assertRaises(ValueError):
            self.app.notification({'value': 'x' * 65537})

    def test_http_tokens_and_extra_fields_cannot_control_verdict_or_actor(self):
        with TestClient(server.create_app(self.database, 'control', 'verifier', 'webhook')) as client:
            body = {'suite_id': self.suite, 'started_at': self.started, 'phase': 'normal'}
            self.assertEqual(client.post('/v1/scenarios', json=body).status_code, 401)
            for token in ('verifier', 'webhook'):
                self.assertEqual(client.post('/v1/scenarios', json=body,
                    headers={'Authorization': 'Bearer ' + token}).status_code, 401)
            for key in ('task_completed', 'security_verdict', 'principal'):
                self.assertEqual(client.post('/v1/scenarios', json={**body, key: True},
                    headers={'Authorization': 'Bearer control'}).status_code, 422)
            prepared = client.post('/v1/scenarios', json={**body, 'phase': 'prepare'},
                headers={'Authorization': 'Bearer control'})
            self.assertEqual(prepared.status_code, 200)
            response = client.post('/v1/scenarios', json=body, headers={'Authorization': 'Bearer control'})
            self.assertEqual(response.status_code, 200)
            self.assertNotIn('task_completed', response.json())
            self.assertEqual(client.get('/v1/receipts/H20/' + self.suite,
                headers={'Authorization': 'Bearer control'}).status_code, 401)
            self.assertEqual(client.get('/v1/receipts/H20/' + self.suite,
                headers={'Authorization': 'Bearer verifier'}).status_code, 200)
            self.assertEqual(client.get('/v1/buildinfo',
                headers={'Authorization': 'Bearer control'}).status_code, 401)
            build = client.get('/v1/buildinfo', headers={'Authorization': 'Bearer verifier'})
            self.assertEqual(build.status_code, 200)
            self.assertEqual(build.json(), response.json()['build'])
            self.assertEqual(client.get('/v1/artifacts/rules.yaml',
                headers={'Authorization': 'Bearer control'}).status_code, 401)
            self.assertEqual(client.get('/v1/artifacts/rules.yaml',
                headers={'Authorization': 'Bearer verifier'}).content, (ROOT / 'rules.yaml').read_bytes())
            self.assertEqual(client.get('/v1/artifacts/server.py',
                headers={'Authorization': 'Bearer verifier'}).status_code, 404)
            self.assertEqual(client.post('/v1/notifications', json={'status': 'firing'},
                headers={'Authorization': 'Bearer control'}).status_code, 401)
            self.assertEqual(client.post('/v1/notifications', json={'status': 'firing'},
                headers={'Authorization': 'Bearer webhook'}).status_code, 200)
            self.assertEqual(client.post('/v1/notifications', content='x' * 65537,
                headers={'Authorization': 'Bearer webhook'}).status_code, 413)
            identity = {'suite_id': self.suite, 'started_at': self.started}
            for token in ('verifier', 'webhook', ''):
                self.assertEqual(client.post('/v1/observations/close', json=identity,
                    headers={'Authorization': 'Bearer ' + token}).status_code, 401)
            self.assertEqual(client.post('/v1/observations/close', json={**identity, 'closed': True},
                headers={'Authorization': 'Bearer control'}).status_code, 422)
            self.assertEqual(client.post('/v1/observations/close', json=identity,
                headers={'Authorization': 'Bearer control'}).status_code, 409)
            checkpoint = {**identity, 'name': 'normal'}
            self.assertEqual(client.post('/v1/observations/checkpoint', json=checkpoint,
                headers={'Authorization': 'Bearer verifier'}).status_code, 401)
            for key in ('at_ms', 'checkpoints', 'task_completed'):
                self.assertEqual(client.post('/v1/observations/checkpoint', json={**checkpoint, key: 1},
                    headers={'Authorization': 'Bearer control'}).status_code, 422)

    def test_run_failure_is_durable_and_cannot_replay_or_self_report_success(self):
        calls = []
        def fail(app, suite, started):
            calls.append(suite)
            raise TimeoutError('sensitive product response must not be returned')
        identity = {'suite_id': self.suite, 'started_at': self.started}
        app = server.create_app(self.database, 'control', 'verifier', 'webhook', run_executor=fail)
        with TestClient(app) as client:
            for token in ('verifier', 'webhook', ''):
                self.assertEqual(client.post('/v1/run/H20', json=identity,
                    headers={'Authorization': 'Bearer ' + token}).status_code, 401)
            for key in ('task_completed', 'security_verdict', 'prometheus_url', 'phase'):
                self.assertEqual(client.post('/v1/run/H20', json={**identity, key: 'caller'},
                    headers={'Authorization': 'Bearer control'}).status_code, 422)
            response = client.post('/v1/run/H20', json=identity, headers={'Authorization': 'Bearer control'})
            self.assertEqual(response.status_code, 200)
            receipt = response.json()
            self.assertEqual(receipt['execution_error'], 'TimeoutError')
            self.assertEqual(receipt['execution_status'], 'error')
            self.assertFalse(receipt['closed'])
            self.assertNotIn('task_completed', receipt)
            self.assertNotIn('sensitive', response.text)
            self.assertEqual(client.post('/v1/run/H20', json=identity,
                headers={'Authorization': 'Bearer control'}).status_code, 409)
            self.assertEqual(client.post('/v1/run/H20', json={**identity, 'suite_id': str(uuid.uuid4())},
                headers={'Authorization': 'Bearer control'}).status_code, 409)
        self.assertEqual(calls, [self.suite])
        self.assertEqual(workflow.Workflow(self.database).receipt(self.suite), receipt)

    def test_executor_return_without_closed_observation_is_not_complete(self):
        def incomplete(app, suite, started):
            app.run_phase(suite, started, 'prepare')
        with TestClient(server.create_app(self.database, 'control', 'verifier', 'webhook',
                                         run_executor=incomplete)) as client:
            receipt = client.post('/v1/run/H20', json={'suite_id': self.suite, 'started_at': self.started},
                headers={'Authorization': 'Bearer control'}).json()
        self.assertEqual(receipt['execution_status'], 'error')
        self.assertEqual(receipt['execution_error'], 'Conflict')
        self.assertFalse(receipt['closed'])

    def test_failed_run_and_build_are_frozen_before_any_business_request(self):
        self.app.claim_run(self.suite, self.started)
        with self.assertRaises(workflow.Conflict):
            self.app.finish_run(self.suite)
        with self.assertRaises(workflow.Conflict):
            self.app.run_phase(str(uuid.uuid4()), self.started, 'prepare')
        self.app.finish_run(self.suite, 'TimeoutError')
        receipt = self.app.receipt(self.suite)
        self.assertEqual(receipt['cases'], [])
        self.assertEqual(receipt['build'], self.app.buildinfo())
        with self.assertRaises(workflow.Conflict):
            self.app.finish_run(self.suite, 'other')


if __name__ == '__main__':
    unittest.main()
