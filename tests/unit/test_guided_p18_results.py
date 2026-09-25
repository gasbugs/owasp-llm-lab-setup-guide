"""P18 semantic result contracts using explicit product-shaped fixtures."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-evidence-verifier/p18_results.py'
spec = importlib.util.spec_from_file_location('p18_results_test', PATH)
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


class P18ResultsTests(unittest.TestCase):
    def setUp(self):
        self.case = {'request_id': 'request-one', 'trace_id': 'a' * 32, 'decision': 'block',
                     'started_ns': 100, 'finished_ns': 200}
        self.log = {'status': 'success', 'data': {'resultType': 'streams', 'result': [{
            'stream': {'service_name': 'guided-h18-queries'},
            'values': [['150', 'security_decision', {'request_id': 'request-one', 'trace_id': 'a' * 32,
                       'decision': 'block', 'policy_rule': 'notice-read-only'}]],
        }]}}

    def trace(self, decision='block'):
        def span(name, span_id, parent=None):
            item = {'name': name, 'spanId': span_id, 'traceId': 'a' * 32, 'attributes': [
                {'key': 'request_id', 'value': {'stringValue': 'request-one'}},
                {'key': 'decision', 'value': {'stringValue': decision}}]}
            if parent:
                item['parentSpanId'] = parent
            return item
        spans = [span('security.request', '1' * 16), span('authorize', '2' * 16, '1' * 16)]
        if decision == 'allow':
            spans.append(span('notice_lookup', '3' * 16, '1' * 16))
        return {'batches': [{'scopeSpans': [{'spans': spans}]}]}

    def metric(self, allow, block):
        return {'status': 'success', 'data': {'resultType': 'vector', 'result': [
            {'metric': {'decision': decision, 'hands_on': 'H18'}, 'value': [10, str(value)]}
            for decision, value in (('allow', allow), ('block', block))]}}

    def test_exact_current_log_matches(self):
        self.assertEqual(checks.check_logs(self.log, self.case), 1)

    def test_foreign_or_missing_logs_are_rejected(self):
        for key in ('request_id', 'trace_id', 'decision', 'policy_rule'):
            payload = deepcopy(self.log)
            payload['data']['result'][0]['values'][0][2][key] = 'foreign'
            with self.subTest(key=key), self.assertRaises(ValueError):
                checks.check_logs(payload, self.case)
        with self.assertRaises(ValueError):
            checks.check_logs({'status': 'success', 'data': {'resultType': 'streams', 'result': []}}, self.case)

    def test_log_from_outside_execution_window_is_rejected(self):
        self.log['data']['result'][0]['values'][0][0] = '99'
        with self.assertRaises(ValueError):
            checks.check_logs(self.log, self.case)

    def test_trace_requires_parent_link_and_denied_downstream_absence(self):
        self.assertEqual(set(checks.check_trace(self.trace(), self.case)), {'security.request', 'authorize'})
        with self.assertRaises(ValueError):
            checks.check_trace(self.trace('allow'), self.case)
        broken = self.trace()
        broken['batches'][0]['scopeSpans'][0]['spans'][1]['parentSpanId'] = '9' * 16
        with self.assertRaises(ValueError):
            checks.check_trace(broken, self.case)

    def test_normal_trace_requires_actual_lookup(self):
        case = {**self.case, 'decision': 'allow'}
        self.assertIn('notice_lookup', checks.check_trace(self.trace('allow'), case))
        with self.assertRaises(ValueError):
            checks.check_trace(self.trace(), case)

    def test_counter_checks_both_deltas_not_existing_nonzero_values(self):
        self.assertEqual(checks.check_counter_change(self.metric(7, 10), self.metric(8, 11)), {'allow': 1, 'block': 1})
        for after in (self.metric(7, 10), self.metric(8, 10), self.metric(8, 12), self.metric(0, 0)):
            with self.subTest(after=after), self.assertRaises(ValueError):
                checks.check_counter_change(self.metric(7, 10), after)

    def test_scalar_nan_and_missing_counter_series_are_rejected(self):
        for payload in ({'status': 'success', 'data': {'resultType': 'scalar', 'result': [10, '2']}},
                        self.metric('nan', 1), self.metric('inf', 1)):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                checks.counter_values(payload)

    def test_ledger_requires_closed_distinct_cases_and_real_normal_result(self):
        normal = {**self.case, 'decision': 'allow', 'closed': True, 'downstream_called': True,
                  'result': {'notice_id': 'training-notice'}}
        denied = {**self.case, 'request_id': 'request-two', 'trace_id': 'b' * 32,
                  'closed': True, 'downstream_called': False, 'result': None}
        receipt = {'activity_id': 'P18', 'contract_version': 2, 'suite_id': 'suite', 'started_at': 'now',
                   'cases': [normal, denied]}
        ledger = {'suite_id': 'suite', 'started_at': 'now', 'closed': True, 'cases': [normal, denied],
                  'downstream_calls': [{'operation': 'notice_lookup', 'request_id': normal['request_id'],
                                        'trace_id': normal['trace_id'], 'result': normal['result']}]}
        self.assertEqual(len(checks.check_ledger(receipt, ledger)), 2)
        for key, value in (('closed', False), ('downstream_calls', []), ('suite_id', 'other')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                checks.check_ledger(receipt, {**ledger, key: value})


if __name__ == '__main__':
    unittest.main()
