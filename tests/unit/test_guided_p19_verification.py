"""Verifier contract fixtures; positive values here are not learner E2E proof."""
import copy
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import time
import tempfile
import unittest
import uuid

PATH = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-evidence-verifier/p19_verification.py'
spec = importlib.util.spec_from_file_location('p19_verification', PATH)
verification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verification)


class P19VerificationTests(unittest.TestCase):
    def setUp(self):
        self.started = datetime.now(timezone.utc).isoformat()
        self.suite = str(uuid.uuid4())
        cases, logs, spans, calls = [], [], [], []
        for index, stop in enumerate((None, 'authorize', 'authenticate')):
            identity = {'request_id': str(uuid.uuid4()), 'trace_id': f'{index + 1:032x}'}
            stages = ['authenticate', 'authorize', 'notice_lookup'][:3 - index]
            log = {**identity, 'decision': 'allow' if stop is None else 'block', 'stop_stage': stop}
            case = {**log, 'closed': True, 'downstream_count': 1 if index == 0 else 0,
                    'started_ns': time.time_ns(), 'finished_ns': time.time_ns(),
                    'result': {'notice_id': 'p19-training-notice'} if index == 0 else None}
            cases.append(case)
            logs.append(log)
            spans.extend({**identity, 'stage': stage, 'sequence': seq} for seq, stage in enumerate(stages, 1))
            if index == 0:
                calls.append({**identity, 'operation': 'notice_lookup', 'result': case['result']})
        self.bundle = {'logs': logs, 'spans': spans, 'closures': cases, 'downstream_calls': calls}
        self.runner = {'provided.py': 'd' * 64}
        self.build = {'source_digest': 'a' * 64, 'runner_digests': self.runner}
        self.ledger = {'suite_id': self.suite, 'started_at': self.started, 'closed': True,
                       'cases': cases, 'downstream_calls': calls}
        executions = []
        for item in verification.INPUTS.build_inputs(self.bundle, [case['request_id'] for case in cases]):
            result = {'execution_status': 'invalid_evidence'} if item['expected_invalid'] else {
                'execution_status': 'returned', 'value': verification.RESULTS.expected_analysis(item['bundle'], item['request_id'])}
            executions.append({key: value for key, value in item.items() if key != 'bundle'}
                              | result | {'source_digest': self.build['source_digest']})
        self.receipt = {'activity_id': 'P19', 'internal_activity_id': 'H19', 'contract_version': 2,
                        'suite_id': self.suite, 'started_at': self.started, 'source_digest': self.build['source_digest'],
                        'cases': cases, 'bundle': self.bundle, 'analysis_executions': executions}

    def verify(self):
        return verification.verify(self.receipt, self.ledger, self.build, {'bundle': self.bundle},
                                   suite_id=self.suite, started_at=self.started, runner_digests=self.runner)

    def test_all_ten_requirements_complete_only_after_baseline_checks(self):
        result = self.verify()
        self.assertTrue(result['task_completed'])
        self.assertEqual(result['security_verdict'], 'PASS')
        self.assertEqual(len(result['checks']), 10)

    def test_actual_alternative_function_executes_all_ten_inputs(self):
        root = PATH.parents[2]
        runner_path = root / 'llm-security-control-plane/guided-labs/h19-incident-investigation/execution.py'
        runner_spec = importlib.util.spec_from_file_location('p19_execution_test', runner_path)
        runner = importlib.util.module_from_spec(runner_spec)
        runner_spec.loader.exec_module(runner)
        source = root / 'tests/e2e/fixtures/p19_analysis.py'
        executions = []
        for item in verification.INPUTS.build_inputs(self.bundle, [case['request_id'] for case in self.ledger['cases']]):
            executed = runner.execute(source, item['bundle'], item['request_id'])
            executions.append({key: value for key, value in item.items() if key != 'bundle'} | executed)
        self.build['source_digest'] = executions[0]['source_digest']
        self.receipt.update(source_digest=self.build['source_digest'], analysis_executions=executions)
        self.assertTrue(self.verify()['task_completed'])
        self.assertEqual([row['execution_status'] for row in executions].count('returned'), 6)
        self.assertEqual([row['execution_status'] for row in executions].count('invalid_evidence'), 4)

        # Comment-only changes alter execution identity, not answer correctness.
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / 'investigation.py'
            changed.write_text(source.read_text() + '\n# Equivalent implementation.\n')
            item = verification.INPUTS.build_inputs(self.bundle, [self.ledger['cases'][0]['request_id']])[0]
            actual = runner.execute(changed, item['bundle'], item['request_id'])
            self.assertNotEqual(actual['source_digest'], self.build['source_digest'])
            self.assertTrue(verification.RESULTS.check_analysis(item['bundle'], item['request_id'], actual)['analysis_correct'])

    def test_source_and_runner_changes_are_rejected(self):
        for key, value in [('source_digest', 'b' * 64), ('runner_digests', {})]:
            original = copy.deepcopy(self.build)
            self.build[key] = value
            with self.subTest(key=key), self.assertRaises(verification.RESULTS.EvidenceMismatch):
                self.verify()
            self.build = original

    def test_missing_duplicate_and_mismatched_analyses_are_rejected(self):
        original = copy.deepcopy(self.receipt['analysis_executions'])
        variants = [original[:-1], [original[0]] * 10,
                    [{**original[0], 'source_digest': 'b' * 64}, *original[1:]],
                    [{**original[0], 'input_digest': 'b' * 64}, *original[1:]],
                    [{**original[0], 'expected_invalid': True}, *original[1:]],
                    [{**original[0], 'execution_status': 'invalid_evidence'}, *original[1:]]]
        for rows in variants:
            self.receipt['analysis_executions'] = rows
            with self.assertRaises(verification.RESULTS.EvidenceMismatch):
                self.verify()

    def test_old_identity_or_real_collection_error_is_not_negative_case_success(self):
        for key, value in [('suite_id', str(uuid.uuid4())), ('execution_error', 'TimeoutError')]:
            receipt = copy.deepcopy(self.receipt)
            self.receipt[key] = value
            with self.subTest(key=key), self.assertRaises(verification.RESULTS.EvidenceMismatch):
                self.verify()
            self.receipt = receipt

    def test_changed_bundle_and_open_ledger_are_rejected(self):
        self.receipt['bundle'] = copy.deepcopy(self.bundle)
        self.receipt['bundle']['logs'][0]['decision'] = 'block'
        with self.assertRaises(verification.RESULTS.EvidenceMismatch):
            self.verify()
        self.receipt['bundle'] = self.bundle
        self.ledger['closed'] = False
        with self.assertRaises(verification.RESULTS.EvidenceMismatch):
            self.verify()


if __name__ == '__main__':
    unittest.main()
