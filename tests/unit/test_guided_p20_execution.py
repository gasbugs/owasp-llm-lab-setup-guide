"""Deterministic orchestration checks, distinct from native product E2E."""
import importlib.util
from pathlib import Path
import unittest

import httpx

ROOT = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-labs/h20-alert-dashboard'
spec = importlib.util.spec_from_file_location('p20_execution', ROOT / 'execution.py')
execution = importlib.util.module_from_spec(spec)
spec.loader.exec_module(execution)


class Clock:
    value = 0.0
    def now(self): return self.value
    def sleep(self, seconds): self.value += seconds


class Workflow:
    def __init__(self, clock):
        self.clock, self.phase, self.risk_at, self.calls = clock, 'initial', None, []
    def run_phase(self, suite, started, phase):
        self.phase = phase
        self.calls.append(phase)
        if phase == 'risk': self.risk_at = self.clock.now()
    def mark_checkpoint(self, suite, started, name): self.calls.append('checkpoint:' + name)
    def close_observation(self, suite, started):
        self.calls.append('close')
        return {'suite_id': suite, 'closed': True}


class P20ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.workflow = Workflow(self.clock)
        self.fault = None
        self.requests = []

    def transport(self, request):
        self.requests.append(request)
        path, flow = request.url.path, self.workflow
        if path == '/api/v1/query':
            counts = {('P20', 'allow'): 10, ('P20', 'block'): 4,
                      ('background', 'allow'): 3, ('background', 'block'): 20}
            if flow.phase in ('normal', 'risk', 'recovery'):
                counts[('P20', 'allow')] += 1
                counts[('background', 'block')] += 3
            if flow.phase in ('risk', 'recovery'): counts[('P20', 'block')] += 2
            if flow.phase == 'recovery': counts[('P20', 'allow')] += 1
            rows = [{'metric': {'practice': p, 'decision': d}, 'value': [self.clock.now(), str(n)]}
                    for (p, d), n in counts.items()]
            if self.fault == 'counter': rows[0]['value'][1] = 'NaN'
            return httpx.Response(200, json={'status': 'success', 'data': {'resultType': 'vector', 'result': rows}})
        if path == '/api/v1/alerts':
            elapsed = None if flow.risk_at is None else self.clock.now() - flow.risk_at
            state = ('inactive' if elapsed is None or elapsed >= 20 else 'pending' if elapsed < 5 else 'firing')
            if self.fault == 'missing-pending' and elapsed is not None and elapsed < 20: state = 'firing'
            if self.fault == 'normal-alert' and flow.phase == 'normal': state = 'firing'
            if self.fault == 'never-alert': state = 'inactive'
            rows = [] if state == 'inactive' else [{'state': state, 'labels': {
                'alertname': 'GuidedP20BlockedRequests', 'practice': 'P20', 'severity': 'warning'}}]
            return httpx.Response(200, json={'status': 'success', 'data': {'alerts': rows}})
        if path == '/api/v2/alerts':
            rows = [] if self.fault == 'no-delivery' else [{'labels': {
                'alertname': 'GuidedP20BlockedRequests', 'practice': 'P20'}, 'status': {'state': 'active'}}]
            return httpx.Response(200, json=rows)
        raise AssertionError(str(request.url))

    def run_execution(self):
        with httpx.Client(transport=httpx.MockTransport(self.transport)) as client:
            return execution.execute(self.workflow, 'suite', 'started', prometheus_url='http://prometheus',
                alertmanager_url='http://alertmanager', client=client, clock=self.clock.now, sleep=self.clock.sleep)

    def test_nonzero_baseline_and_native_phase_order(self):
        receipt = self.run_execution()
        self.assertTrue(receipt['closed'])
        self.assertEqual(self.workflow.calls, ['prepare', 'normal', 'checkpoint:normal', 'risk',
            'recovery', 'checkpoint:after_requests', 'close'])
        self.assertLess(self.clock.now(), 120)
        self.assertTrue(all(request.method == 'GET' for request in self.requests))

    def test_missing_pending_or_firing_is_bounded_and_never_reaches_recovery(self):
        for fault in ('missing-pending', 'never-alert'):
            self.setUp()
            self.fault = fault
            with self.subTest(fault=fault), self.assertRaises(TimeoutError): self.run_execution()
            self.assertNotIn('recovery', self.workflow.calls)
            self.assertLess(self.clock.now(), 120)

    def test_normal_false_positive_stops_before_risk(self):
        self.fault = 'normal-alert'
        with self.assertRaises(ValueError): self.run_execution()
        self.assertEqual(self.workflow.calls, ['prepare', 'normal'])

    def test_invalid_counter_does_not_start_requests(self):
        self.fault = 'counter'
        with self.assertRaises(ValueError): self.run_execution()
        self.assertEqual(self.workflow.calls, [])

    def test_missing_alertmanager_delivery_does_not_claim_recovery(self):
        self.fault = 'no-delivery'
        with self.assertRaises(TimeoutError): self.run_execution()
        self.assertNotIn('recovery', self.workflow.calls)
        self.assertNotIn('close', self.workflow.calls)


if __name__ == '__main__':
    unittest.main()
