import copy
import json
import runpy
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/tests/evaluation/garak-batch.py'


def completed_response(stop='stop'):
    return {'application_decision': 'allow', 'upstream_called': True,
            'guardrail': {'stages': [{'stage': 'bedrock_main', 'stop_reason': stop}]}}


def attempt(*responses):
    return {'entry_type': 'attempt', 'status': 2,
            'outputs': [{'text': json.dumps(response)} for response in responses]}


class GarakBatchTests(unittest.TestCase):
    def execute(self, batch=7, cap=16, generations=1, rows=None):
        selected = []
        configuration = types.SimpleNamespace(run=types.SimpleNamespace(generations=generations))
        class Probe:
            def __init__(self, config_root=None):
                self.prompts = [f'prompt-{index}' for index in range(cap)]
                self.pi_prompts = [{'prompt': prompt} for prompt in self.prompts]
        class Rest:
            def __init__(self, uri=None, config_root=None):
                self.retry_5xx = True
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'report.jsonl'
            configuration.transient = types.SimpleNamespace(reportfile=types.SimpleNamespace(name=str(report)))
            def main(arguments):
                probe = Probe()
                selected.extend(probe.prompts)
                self.assertEqual([row['prompt'] for row in probe.pi_prompts], selected)
                self.assertFalse(Rest().retry_5xx)
                records = rows if rows is not None else [attempt(*[completed_response() for _ in range(generations)]) for _ in selected]
                report.write_text('\n'.join(json.dumps(row) for row in records))
            garak = types.ModuleType('garak')
            garak._config = configuration
            garak.cli = types.SimpleNamespace(main=main)
            probes = types.ModuleType('garak.probes')
            probes.promptinject = types.SimpleNamespace(HijackHateHumans=Probe)
            generators = types.ModuleType('garak.generators')
            rest = types.ModuleType('garak.generators.rest')
            rest.RestGenerator = Rest
            modules = {'garak': garak, 'garak.probes': probes, 'garak.generators': generators, 'garak.generators.rest': rest}
            with patch.dict(sys.modules, modules), patch.object(sys, 'argv', [str(SCRIPT), str(batch)]):
                runpy.run_path(str(SCRIPT), run_name='__main__')
        return selected

    def test_pool_can_grow_without_eight_candidate_requirement(self):
        self.assertEqual(self.execute(), ['prompt-14', 'prompt-15'])
        self.assertEqual(self.execute(batch=15, cap=32), ['prompt-30', 'prompt-31'])

    def test_out_of_pool_batch_stops_before_generator(self):
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.execute(batch=8)

    def test_missing_attempt_is_error(self):
        with self.assertRaisesRegex(RuntimeError, 'two completed'):
            self.execute(rows=[attempt(completed_response())])

    def test_second_generation_is_checked(self):
        rows = [attempt(completed_response(), completed_response('length')),
                attempt(completed_response(), completed_response())]
        with self.assertRaisesRegex(RuntimeError, 'incomplete'):
            self.execute(generations=2, rows=rows)

    def test_missing_generation_is_error(self):
        with self.assertRaisesRegex(RuntimeError, 'missing generated'):
            self.execute(generations=2, rows=[attempt(completed_response())] * 2)

    def test_application_infrastructure_error_is_not_security_pass(self):
        with self.assertRaisesRegex(RuntimeError, 'security decision'):
            self.execute(rows=[attempt({'application_decision': 'infra'})] * 2)

    def test_input_block_is_valid_without_main_model(self):
        response = {'application_decision': 'block', 'upstream_called': False}
        self.assertEqual(self.execute(rows=[attempt(response)] * 2), ['prompt-14', 'prompt-15'])

    def test_no_response_generation_is_ignored(self):
        self.assertEqual(self.execute(generations=2), ['prompt-14', 'prompt-15'])


if __name__ == '__main__':
    unittest.main()
