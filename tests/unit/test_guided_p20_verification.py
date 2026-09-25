"""Synthetic contract tests; the separate product publisher exercises real products."""
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import hashlib
import json
from pathlib import Path
import time
import unittest
import uuid

import httpx

ROOT = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-evidence-verifier'
spec = importlib.util.spec_from_file_location('p20_verification', ROOT / 'p20_verification.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
R = verifier.RESULTS


def iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


class P20VerificationTests(unittest.TestCase):
    def setUp(self):
        self.start = int(time.time()) - 60
        self.suite = str(uuid.uuid4())
        self.started = iso(self.start)
        self.points = {key: (self.start + delta) * 1000
                       for key, delta in [('baseline', 5), ('normal', 19), ('after_requests', 28)]}
        cases = []
        for phase, offset, practices in [('normal', 10, ['P20', 'background', 'background', 'background']),
                                         ('risk', 20, ['P20', 'P20']), ('recovery', 26, ['P20'])]:
            for ordinal, practice in enumerate(practices):
                allow = phase != 'risk' and practice == 'P20'
                cases.append({'suite_id': self.suite, 'request_id': str(uuid.uuid4()), 'phase': phase,
                    'ordinal': ordinal, 'practice': practice, 'operation': 'notice_lookup' if allow else 'notice_publish',
                    'decision': 'allow' if allow else 'block', 'downstream_count': int(allow),
                    'finished_ns': (self.start + offset) * 1_000_000_000 + ordinal})
        self.receipt = {'suite_id': self.suite, 'started_at': self.started, 'activity_id': 'P20',
            'internal_activity_id': 'H20', 'contract_version': 2, 'closed': True, 'requests_closed': True,
            'observation_closed_ns': (self.start + 41) * 1_000_000_000, 'cases': cases,
            'checkpoints': dict(self.points)}
        artifacts = {'rules.yaml': 'a' * 64, 'dashboard.json': 'b' * 64}
        self.runners = {'server.py': 'c' * 64, 'workflow.py': 'd' * 64, 'execution.py': 'e' * 64}
        self.build = {'artifact_digests': artifacts, 'runner_digests': self.runners,
            'source_digest': hashlib.sha256(json.dumps(artifacts, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
        self.receipt['build'] = deepcopy(self.build)
        self.labels = {'alertname': 'GuidedP20BlockedRequests', 'practice': 'P20', 'severity': 'warning'}
        self.history = {'status': 'success', 'data': {'resultType': 'matrix', 'result': [
            {'metric': {**self.labels, '__name__': 'ALERTS', 'alertstate': state},
             'values': [[self.start + t, '1'] for t in times]}
            for state, times in [('pending', range(21, 25)), ('firing', range(25, 40))]]}}
        self.notifications = [{'received_ns': int((self.start + offset + .1) * 1e9), 'body': {'alerts': [{
            'status': status, 'labels': dict(self.labels), 'fingerprint': 'aabbccdd',
            'startsAt': iso(self.start + 25), 'endsAt': iso(self.start + offset)}]}}
            for status, offset in [('firing', 25), ('resolved', 40)]]
        self.expr = 'sum by (decision) (guided_p20_decisions_total{practice="P20"})'
        self.rule_expr = 'sum(increase(guided_p20_decisions_total{practice="P20",decision="block"}[20s])) > 0'
        self.rule_labels = {'practice': 'P20', 'severity': 'warning'}
        self.sync_sources()
        self.requests = []
        self.mutate = lambda path, raw: raw

    def sync_sources(self):
        rule = {'groups': [{'name': 'p20', 'rules': [{'alert': 'GuidedP20BlockedRequests',
            'expr': self.rule_expr, 'for': '4s', 'labels': self.rule_labels}]}]}
        dashboard = {'uid': 'guided-p20', 'panels': [{'datasource': {'type': 'prometheus', 'uid': 'p20'},
                       'targets': [{'refId': 'A', 'expr': self.expr}]}]}
        self.sources = {'rules.yaml': json.dumps(rule).encode(), 'dashboard.json': json.dumps(dashboard).encode()}
        self.bind_sources()
        body = {'rules': self.native_rules(), 'dashboard': {'dashboard': dashboard}}
        self.receipt['product_snapshots'] = {stage: {'observed_ns': (self.start + offset) * 1_000_000_000,
            'body': deepcopy(body)} for stage, offset in [('before', 4), ('after', 41)]}

    def native_rules(self):
        return {'status': 'success', 'data': {'groups': [{'rules': [{
            'name': 'GuidedP20BlockedRequests', 'type': 'alerting', 'health': 'ok',
            'duration': 4, 'labels': dict(self.rule_labels), 'query': self.rule_expr}]}]}}

    def bind_sources(self):
        artifacts = {name: hashlib.sha256(raw).hexdigest() for name, raw in self.sources.items()}
        self.build = {'artifact_digests': artifacts, 'runner_digests': deepcopy(self.runners),
            'source_digest': hashlib.sha256(json.dumps(artifacts, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
        self.receipt['build'] = deepcopy(self.build)

    def counts(self, at):
        delta = at - self.start
        return {('P20', 'allow'): 10 + (2 if delta >= 26 else 1 if delta >= 10 else 0),
                ('P20', 'block'): 5 + (2 if delta >= 20 else 0),
                ('background', 'allow'): 0, ('background', 'block'): 40 + (3 if delta >= 10 else 0)}

    def transport(self, request):
        path = request.url.path
        self.requests.append(request)
        if path.startswith('/v1/'):
            self.assertEqual(request.headers['Authorization'], 'Bearer reader-token')
        if path.startswith('/v1/artifacts/'):
            return httpx.Response(200, content=self.sources[path.rsplit('/', 1)[1]])
        if path.startswith('/v1/receipts/'):
            raw = deepcopy(self.receipt)
        elif path == '/v1/buildinfo':
            raw = deepcopy(self.build)
        elif path == '/v1/notifications':
            raw = deepcopy(self.notifications)
        elif path == '/api/v1/rules':
            raw = self.native_rules()
        elif path == '/api/v1/format_query':
            raw = {'status': 'success', 'data': request.url.params['query']}
        elif path.startswith('/api/dashboards/'):
            raw = {'dashboard': json.loads(self.sources['dashboard.json'])}
        elif path == '/api/ds/query':
            body = json.loads(request.content)
            self.assertEqual(body['queries'][0]['expr'], self.expr)
            at_ms = int(body['to'])
            raw = {'results': {'A': {'status': 200, 'frames': [
                {'schema': {'fields': [{'type': 'time'}, {'type': 'number', 'labels': {'decision': decision}}]},
                 'data': {'values': [[at_ms], [self.counts(at_ms / 1000)[('P20', decision)]]]}}
                for decision in ('allow', 'block')]}}}
        elif path == '/api/v1/query_range':
            raw = deepcopy(self.history)
        elif path == '/api/v1/query':
            at = float(request.url.params['time'])
            rows = []
            if request.url.params['query'] == 'guided_p20_decisions_total':
                rows = [{'metric': {'__name__': 'guided_p20_decisions_total', 'practice': practice,
                                    'decision': decision}, 'value': [at, str(value)]}
                        for (practice, decision), value in self.counts(at).items()]
            raw = {'status': 'success', 'data': {'resultType': 'vector', 'result': rows}}
        else:
            raise AssertionError('unexpected URL: ' + str(request.url))
        return httpx.Response(200, json=self.mutate(path, raw))

    def verify(self):
        result = {}
        with httpx.Client(transport=httpx.MockTransport(self.transport)) as client:
            verifier.collect_and_verify(self.suite, self.started, client=client,
                app_url='http://app', prometheus_url='http://prometheus', grafana_url='http://grafana',
                verifier_token='reader-token', grafana_auth=('reader', 'test-only'), runner_digests=self.runners, result=result)
        return result

    def test_refetches_products_and_uses_nonzero_counter_baseline(self):
        result = self.verify()
        self.assertTrue(result['product_contract_verified'])
        self.assertNotIn('task_completed', result)
        self.assertEqual(sum(r.url.path == '/api/ds/query' for r in self.requests), 3)
        self.assertTrue(all(r.method == 'GET' or r.url.path == '/api/ds/query' for r in self.requests))

    def test_different_learner_query_is_sent_unchanged(self):
        self.expr = 'sum without(instance, job, practice)(guided_p20_decisions_total{practice="P20"})'
        self.sync_sources()
        self.assertTrue(self.verify()['product_contract_verified'])

    def test_snapshot_missing_changed_and_foreign_time_rejected(self):
        original = deepcopy(self.receipt['product_snapshots'])
        for fault in ('missing', 'rule', 'panel', 'group', 'before-time', 'after-time', 'bool-time'):
            self.receipt['product_snapshots'] = deepcopy(original)
            snapshots = self.receipt['product_snapshots']
            if fault == 'missing': del snapshots['before']
            if fault == 'rule': snapshots['before']['body']['rules']['data']['groups'][0]['rules'][0]['duration'] = 0
            if fault == 'panel': snapshots['after']['body']['dashboard']['dashboard']['panels'] = []
            if fault == 'group': snapshots['after']['body']['rules']['data']['groups'][0]['interval'] = 99
            if fault == 'before-time': snapshots['before']['observed_ns'] = self.start * 1_000_000_000 - 1
            if fault == 'after-time': snapshots['after']['observed_ns'] += 1
            if fault == 'bool-time': snapshots['before']['observed_ns'] = True
            with self.subTest(fault=fault), self.assertRaises(R.EvidenceMismatch):
                self.verify()

    def test_normal_product_state_changes_are_not_configuration_changes(self):
        for stage in ('before', 'after'):
            body = self.receipt['product_snapshots'][stage]['body']
            group = body['rules']['data']['groups'][0]
            group.update(lastEvaluation=stage, evaluationTime=0.2)
            group['rules'][0].update(state=stage, alerts=[{'state': stage}],
                lastEvaluation=stage, evaluationTime=0.2)
            body['dashboard']['meta'] = {'url': '/' + stage}
        self.assertTrue(self.verify()['configuration_continuity']['unchanged'])

    def test_harmless_rule_labels_allowed_when_applied(self):
        self.rule_labels['owner'] = 'training'
        self.sync_sources()
        self.assertTrue(self.verify()['product_contract_verified'])

    def test_failed_recheck_does_not_keep_old_success(self):
        result = {'product_contract_verified': True}
        self.receipt['closed'] = False
        with httpx.Client(transport=httpx.MockTransport(self.transport)) as client:
            with self.assertRaises(R.EvidenceMismatch):
                verifier.collect_and_verify(self.suite, self.started, client=client,
                    app_url='http://app', prometheus_url='http://prometheus', grafana_url='http://grafana',
                    verifier_token='reader-token', grafana_auth=('reader', 'test-only'), runner_digests=self.runners, result=result)
        self.assertFalse(result['product_contract_verified'])

    def test_product_http_failure_is_not_accepted(self):
        def fail(request):
            if request.url.path == '/api/v1/rules':
                return httpx.Response(503, json={'detail': 'unavailable'})
            return self.transport(request)
        with httpx.Client(transport=httpx.MockTransport(fail)) as client:
            with self.assertRaises(httpx.HTTPStatusError):
                verifier.collect_and_verify(self.suite, self.started, client=client,
                    app_url='http://app', prometheus_url='http://prometheus', grafana_url='http://grafana',
                    verifier_token='reader-token', grafana_auth=('reader', 'test-only'), runner_digests=self.runners, result={})

    def test_changed_config_missing_build_and_runner_mismatch_rejected(self):
        original = deepcopy(self.build)
        for fault in ('config', 'missing', 'runner', 'combined'):
            self.build = deepcopy(original)
            self.receipt['build'] = deepcopy(original)
            if fault == 'config': self.build['artifact_digests']['rules.yaml'] = 'e' * 64
            if fault == 'missing': self.receipt['build'] = None
            if fault == 'runner':
                self.build['runner_digests']['server.py'] = 'f' * 64
                self.receipt['build'] = deepcopy(self.build)
            if fault == 'combined':
                self.build['source_digest'] = '0' * 64
                self.receipt['build'] = deepcopy(self.build)
            with self.assertRaises(R.EvidenceMismatch):
                self.verify()

    def test_different_valid_artifact_hash_is_not_compared_to_answer(self):
        self.sources['rules.yaml'] += b'\n# harmless learner comment\n'
        self.bind_sources()
        self.assertTrue(self.verify()['product_contract_verified'])

    def test_artifact_bytes_differ_from_recorded_hash_rejected(self):
        self.sources['rules.yaml'] += b'\n'
        with self.assertRaises(R.EvidenceMismatch):
            self.verify()

    def test_missing_or_out_of_phase_persisted_checkpoints_rejected(self):
        for values in ({}, {**self.points, 'normal': True},
                       {**self.points, 'normal': (self.start + 11) * 1000},
                       {**self.points, 'after_requests': (self.start + 50) * 1000}):
            self.receipt['checkpoints'] = values
            with self.assertRaises(R.EvidenceMismatch):
                self.verify()

    def test_old_product_rule_or_dashboard_rejected(self):
        for fault in ('rule', 'panel', 'context'):
            def mutate(path, raw):
                if fault == 'rule' and path == '/api/v1/rules':
                    raw['data']['groups'][0]['rules'][0]['query'] = 'vector(1)'
                if path.startswith('/api/dashboards/'):
                    if fault == 'panel': raw['dashboard']['panels'][0]['targets'][0]['expr'] = 'vector(0)'
                    if fault == 'context': raw['dashboard']['timezone'] = 'browser'
                return raw
            self.mutate = mutate
            with self.assertRaises(R.EvidenceMismatch):
                self.verify()

    def test_stale_foreign_open_and_wrong_downstream_receipts_rejected(self):
        original = deepcopy(self.receipt)
        for key, value in [('suite_id', str(uuid.uuid4())), ('closed', False),
                           ('requests_closed', False), ('activity_id', 'P19')]:
            self.receipt = {**deepcopy(original), key: value}
            with self.assertRaises(R.EvidenceMismatch):
                self.verify()
        self.receipt = original
        self.receipt['cases'][4]['downstream_count'] = 1
        with self.assertRaises(R.EvidenceMismatch):
            self.verify()
        with self.assertRaises(R.EvidenceMismatch):
            R.check_receipt(original, self.suite, self.started, now=self.start + 181)

    def test_counter_nan_duplicate_and_foreign_labels_rejected(self):
        at = self.start + 5
        raw = self.transport(httpx.Request('GET', 'http://prometheus/api/v1/query',
            params={'query': 'guided_p20_decisions_total', 'time': at})).json()
        for change in ('nan', 'duplicate', 'foreign', 'time'):
            broken = deepcopy(raw)
            row = broken['data']['result'][0]
            if change == 'nan': row['value'][1] = 'NaN'
            if change == 'duplicate': broken['data']['result'].append(deepcopy(row))
            if change == 'foreign': row['metric']['request_id'] = 'foreign'
            if change == 'time': row['value'][0] -= 1
            with self.assertRaises(R.EvidenceMismatch):
                R.counter_values(broken, at)

    def test_constant_panel_and_wrong_frame_time_rejected(self):
        for fault in ('constant', 'timestamp'):
            def mutate(path, raw):
                if path == '/api/ds/query':
                    raw['results']['A']['frames'][0]['data']['values'][1 if fault == 'constant' else 0] = [0]
                return raw
            self.mutate = mutate
            with self.assertRaises(R.EvidenceMismatch):
                self.verify()

    def test_missing_pending_false_positive_and_history_gap_rejected(self):
        original = deepcopy(self.history)
        for fault in ('missing', 'normal', 'gap'):
            self.history = deepcopy(original)
            rows = self.history['data']['result']
            if fault == 'missing': rows.pop(0)
            if fault == 'normal': rows[0]['values'][0][0] = self.start + 12
            if fault == 'gap': rows[1]['values'].pop(2)
            with self.assertRaises(R.EvidenceMismatch):
                self.verify()

    def test_notifications_missing_old_or_mismatched_rejected(self):
        original = deepcopy(self.notifications)
        for fault in ('missing', 'fingerprint', 'old', 'order', 'window'):
            self.notifications = deepcopy(original)
            alert = self.notifications[-1]['body']['alerts'][0]
            if fault == 'missing': self.notifications.pop()
            if fault == 'fingerprint': alert['fingerprint'] = 'foreign'
            if fault == 'old': alert['startsAt'] = iso(self.start - 50)
            if fault == 'order': self.notifications.reverse()
            if fault == 'window': alert['endsAt'] = iso(self.start + 37)
            with self.assertRaises(R.EvidenceMismatch):
                self.verify()


if __name__ == '__main__':
    unittest.main()
