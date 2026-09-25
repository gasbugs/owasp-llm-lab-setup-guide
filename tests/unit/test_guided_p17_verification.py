"""P17 re-fetch semantics, execution identity and measurement interval boundaries."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import time
import unittest
from unittest.mock import Mock
import uuid

import httpx
import test_guided_p17_results as fixtures

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('p17_verification', ROOT /
    'llm-security-control-plane/guided-evidence-verifier/p17_verification.py')
verification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verification)


class P17VerificationTests(unittest.TestCase):
    def setUp(self):
        self.started = datetime.now(timezone.utc).isoformat()
        start = time.time_ns()
        fixture = fixtures.P17ResultTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.products = fixture.products
        self.receipt = {'activity_id': 'P17', 'internal_activity_id': 'H17', 'contract_version': 2,
            'suite_id': str(uuid.uuid4()), 'started_at': self.started,
            'query_start_ns': start, 'query_end_ns': time.time_ns(), 'counter_before': {'allow': 0, 'block': 0},
            'source_digest': fixture.execution['source_digest'], 'execution': fixture.execution}
        self.ledger = {'suite_id': self.receipt['suite_id'], 'started_at': self.started, 'closed': True,
                       'cases': [c['ledger'] for c in fixture.execution['cases']]}
        self.digests = {'server.py': 'provided-server'}
        self.build = {'source_digest': fixture.execution['source_digest'], 'runner_digests': self.digests}
        self.client = Mock()
        self.client.get.side_effect = self.get

    def get(self, url, params=None):
        if url.endswith('/api/v1/query'):
            counts = [0, 0] if params['time'] == self.receipt['query_start_ns']/1e9 else [1, 2]
            value = {'status': 'success', 'data': {'resultType': 'vector', 'result': [
                {'metric': {'__name__': 'guided_p17_decisions_total', 'decision': decision},
                 'value': [params['time'], str(count)]} for decision, count in zip(('allow', 'block'), counts)]}}
        else:
            cases = self.receipt['execution']['cases']
            if '/api/traces/' in url:
                index = next(i for i, c in enumerate(cases) if c['ledger']['stages'][0]['trace_id'] in url)
                value = self.products[index]['tempo']
            else:
                index = next(i for i, c in enumerate(cases) if c['request_id'] in params['query'])
                value = self.products[index]['loki']
        return httpx.Response(200, request=httpx.Request('GET', url), json=value)

    def verify(self):
        result = {}
        verification.identity(self.receipt, self.receipt['suite_id'], self.started)
        verification.collect_and_verify(self.receipt, self.ledger, self.build, self.digests,
            client=self.client, loki_url='http://loki', tempo_url='http://tempo',
            prometheus_url='http://prometheus', result=result, timeout=0)
        return result

    def test_actual_signals_requeried_with_fixed_counter_interval(self):
        result = self.verify()
        self.assertEqual(len(result['cases']), 3)
        self.assertEqual(result['counter_delta'], {'allow': 1, 'block': 2})
        self.assertEqual(self.client.get.call_count, 8)
        times = [c.kwargs['params']['time'] for c in self.client.get.call_args_list if c.args[0].endswith('/api/v1/query')]
        self.assertEqual(times, [self.receipt['query_start_ns']/1e9, self.receipt['query_end_ns']/1e9])
        queries = [c.kwargs['params']['query'] for c in self.client.get.call_args_list
                   if c.args[0].endswith('/loki/api/v1/query_range')]
        self.assertEqual(len(queries), 3)
        self.assertTrue(all(' | json | request_id = ' in query for query in queries))

    def test_foreign_identity_and_history_rejected(self):
        for suite, started in [('other', self.started),
                               (self.receipt['suite_id'], '2000-01-01T00:00:00+00:00')]:
            with self.subTest(suite=suite), self.assertRaises(verification.RESULTS.EvidenceMismatch):
                verification.identity(self.receipt, suite, started)
        self.receipt['started_at'] = (datetime.now(timezone.utc)-timedelta(minutes=5)).isoformat()
        with self.assertRaises(verification.RESULTS.EvidenceMismatch):
            verification.identity(self.receipt, self.receipt['suite_id'], self.receipt['started_at'])

    def test_execution_and_source_mismatch_before_product_queries(self):
        for mutation in ('source', 'runner', 'open', 'starter', 'repeat_request', 'wrong_case', 'future', 'ledger'):
            with self.subTest(mutation=mutation):
                original = copy.deepcopy((self.receipt, self.ledger, self.build))
                if mutation == 'source': self.build['source_digest'] = 'f'*64
                elif mutation == 'runner': self.build['runner_digests'] = {}
                elif mutation == 'open': self.ledger['closed'] = False
                elif mutation == 'starter': self.receipt['execution']['cases'][0]['execution_status'] = 'not_implemented'
                elif mutation == 'repeat_request': self.receipt['execution']['cases'][1]['request_id'] = self.receipt['execution']['cases'][0]['request_id']
                elif mutation == 'wrong_case': self.receipt['execution']['cases'][0]['action'] = 'notice_publish'
                elif mutation == 'future': self.receipt['query_end_ns'] = time.time_ns()+10**12
                else: self.ledger['suite_id'] = 'another'
                with self.assertRaises(verification.RESULTS.EvidenceMismatch): self.verify()
                self.client.get.assert_not_called()
                self.receipt, self.ledger, self.build = original

    def test_changed_learner_digest_is_not_compared_with_an_answer_hash(self):
        for value in (self.receipt, self.receipt['execution'], self.build):
            value['source_digest'] = 'c'*64
        self.assertEqual(len(self.verify()['cases']), 3)


if __name__ == '__main__':
    unittest.main()
