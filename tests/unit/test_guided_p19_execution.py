"""Execute actual local learner edits, without products, AWS, or a course verdict."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-labs/h19-incident-investigation/execution.py'
spec = importlib.util.spec_from_file_location('p19_execution', PATH)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class P19ExecutionTests(unittest.TestCase):
    def run_source(self, source, bundle=None, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'investigation.py'
            path.write_text(source)
            result = runner.execute(path, bundle or {}, 'current-request', **kwargs)
        self.assertEqual(result['source_digest'], hashlib.sha256(source.encode()).hexdigest())
        self.assertNotIn('task_completed', result)
        self.assertNotIn('security_verdict', result)
        return result

    def test_runs_two_real_implementations_not_source_hash_comparison(self):
        sources = [
            'def analyze_incident(bundle, request_id):\n return {"ids": [r["request_id"] for r in bundle["logs"] if r["request_id"] == request_id]}\n',
            '# An equivalent implementation with different whitespace.\ndef analyze_incident(bundle, request_id):\n rows = filter(lambda r: r["request_id"] == request_id, bundle["logs"])\n return {"ids": list(map(lambda r: r["request_id"], rows))}\n',
        ]
        bundle = {'logs': [{'request_id': 'foreign'}, {'request_id': 'current-request'}]}
        results = [self.run_source(source, bundle) for source in sources]
        self.assertNotEqual(results[0]['source_digest'], results[1]['source_digest'])
        for result in results:
            self.assertEqual(result['execution_status'], 'returned')
            self.assertEqual(result['value'], {'ids': ['current-request']})

    def test_runner_does_not_grade_or_correct_wrong_answer(self):
        result = self.run_source('def analyze_incident(bundle, request_id):\n return {"request_id": "foreign"}\n')
        self.assertEqual(result['value'], {'request_id': 'foreign'})

    def test_starter_and_invalid_evidence_are_distinct(self):
        for exception, status in [('NotImplementedError', 'not_implemented'), ('ValueError', 'invalid_evidence'),
                                  ('RuntimeError', 'runtime_error')]:
            with self.subTest(exception=exception):
                result = self.run_source(f'def analyze_incident(bundle, request_id):\n raise {exception}("private detail")\n')
                self.assertEqual(result['execution_status'], status)
                self.assertNotIn('private detail', str(result))

    def test_syntax_exit_and_wrong_return_do_not_crash_parent(self):
        for source in ('invalid syntax!', 'raise SystemExit(0)',
                       'raise ValueError("module load failed")',
                       'def analyze_incident(bundle, request_id):\n return {"number": float("nan")}\n',
                       'def analyze_incident(bundle, request_id):\n return []\n'):
            self.assertEqual(self.run_source(source)['execution_status'], 'runtime_error')

    def test_stdout_and_environment_are_not_receipt_channels(self):
        with patch.dict(os.environ, {'GUIDED_TEST_SECRET': 'not-for-learner'}):
            result = self.run_source('import os\nprint("not JSON")\ndef analyze_incident(bundle, request_id):\n return {"secret": os.getenv("GUIDED_TEST_SECRET")}\n')
        self.assertEqual(result['value'], {'secret': None})

    def test_input_mutation_does_not_change_parent_evidence(self):
        bundle = {'logs': ['preserve']}
        self.run_source('def analyze_incident(bundle, request_id):\n bundle["logs"].clear()\n return {}\n', bundle)
        self.assertEqual(bundle, {'logs': ['preserve']})

    def test_time_and_size_limits(self):
        self.assertEqual(self.run_source('while True: pass', timeout=0.15)['execution_status'], 'timeout')
        self.assertEqual(self.run_source('#' * (runner.SOURCE_LIMIT + 1))['execution_status'], 'source_limit')
        self.assertEqual(self.run_source('', {'logs': ['x' * runner.INPUT_LIMIT]})['execution_status'], 'input_limit')
        self.assertEqual(self.run_source('def analyze_incident(bundle, request_id):\n return {"huge": "x" * 65536}\n')['execution_status'], 'output_limit')


if __name__ == '__main__':
    unittest.main()
