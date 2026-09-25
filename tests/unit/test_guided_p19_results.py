"""Contract fixtures only; these are not evidence of running Loki or Tempo."""
import copy
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-evidence-verifier/p19_results.py'
spec = importlib.util.spec_from_file_location('p19_results', PATH)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class P19ResultsTests(unittest.TestCase):
    def fixture(self, blocked=False):
        identity = {'request_id': 'this-request', 'trace_id': 'this-trace'}
        stages = ['authenticate', 'authorize'] if blocked else ['authenticate', 'authorize', 'notice_lookup']
        count = 0 if blocked else 1
        bundle = {
            'logs': [{**identity, 'decision': 'block' if blocked else 'allow',
                      'stop_stage': 'authorize' if blocked else None}],
            'spans': [{**identity, 'stage': stage, 'sequence': index}
                      for index, stage in reversed(list(enumerate(stages, 1)))],
            'closures': [{**identity, 'closed': True, 'downstream_count': count}],
            'downstream_calls': [] if blocked else [{**identity, 'operation': 'notice_lookup'}],
        }
        for rows in bundle.values():
            rows.insert(0, {'request_id': 'another-request', 'trace_id': 'another-trace'})
        expected = {**identity, 'decision': 'block' if blocked else 'allow', 'stages': stages,
                    'stop_stage': 'authorize' if blocked else None, 'downstream_count': count}
        return bundle, expected

    def test_normal_and_denied_requests_ignore_unrelated_records_and_sort(self):
        for blocked in (False, True):
            bundle, expected = self.fixture(blocked)
            result = contract.check_analysis(bundle, 'this-request', {'execution_status': 'returned', 'value': expected})
            self.assertTrue(result['analysis_correct'])
            self.assertEqual(result['analysis'], expected)

    def test_wrong_request_stage_count_and_type_are_not_corrected(self):
        bundle, expected = self.fixture()
        for field, value in [('request_id', 'another-request'), ('trace_id', 'another-trace'),
                             ('stages', ['authorize']), ('stop_stage', 'authorize'),
                             ('downstream_count', True), ('downstream_count', 0), ('decision', 'block')]:
            with self.subTest(field=field, value=value), self.assertRaises(contract.EvidenceMismatch):
                contract.check_analysis(bundle, 'this-request',
                                        {'execution_status': 'returned', 'value': {**expected, field: value}})

    def test_missing_duplicate_unclosed_and_mixed_trace_are_invalid(self):
        baseline, _ = self.fixture()
        damaged = []
        for key in ('logs', 'spans', 'closures'):
            value = copy.deepcopy(baseline)
            value[key] = []
            damaged.append(value)
        for key in ('logs', 'closures', 'spans'):
            value = copy.deepcopy(baseline)
            value[key].append(copy.deepcopy(value[key][-1]))
            damaged.append(value)
        for key, field, replacement in [('closures', 'closed', False), ('closures', 'downstream_count', 0),
                                        ('spans', 'trace_id', 'foreign'), ('downstream_calls', 'trace_id', 'foreign'),
                                        ('spans', 'sequence', True), ('logs', 'decision', 'unknown')]:
            value = copy.deepcopy(baseline)
            value[key][-1][field] = replacement
            damaged.append(value)
        for index, bundle in enumerate(damaged):
            with self.subTest(index=index):
                with self.assertRaises(contract.EvidenceMismatch):
                    contract.check_analysis(bundle, 'this-request', {'execution_status': 'invalid_evidence'})
                self.assertTrue(contract.check_analysis(bundle, 'this-request',
                    {'execution_status': 'invalid_evidence'}, expected_invalid=True)['analysis_correct'])
                with self.assertRaises(contract.EvidenceMismatch):
                    contract.check_analysis(bundle, 'this-request',
                        {'execution_status': 'returned', 'value': {}}, expected_invalid=True)

    def test_deny_all_and_false_negative_fixture_are_rejected(self):
        bundle, expected = self.fixture()
        with self.assertRaises(contract.EvidenceMismatch):
            contract.check_analysis(bundle, 'this-request', {'execution_status': 'invalid_evidence'})
        with self.assertRaises(contract.EvidenceMismatch):
            contract.check_analysis(bundle, 'this-request',
                {'execution_status': 'invalid_evidence'}, expected_invalid=True)

    def test_block_after_downstream_does_not_invent_zero_calls(self):
        bundle, expected = self.fixture()
        bundle['logs'][-1].update(decision='block', stop_stage='notice_lookup')
        expected.update(decision='block', stop_stage='notice_lookup')
        result = contract.check_analysis(bundle, 'this-request', {'execution_status': 'returned', 'value': expected})
        self.assertEqual(result['analysis']['downstream_count'], 1)


if __name__ == '__main__':
    unittest.main()
