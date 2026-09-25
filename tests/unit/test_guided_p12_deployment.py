"""Operational P12 credential placement and packaged read-only verifier config."""
from pathlib import Path
import sys
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = ROOT / 'llm-security-control-plane/guided-evidence-verifier'
sys.path.insert(0, str(DIRECTORY))
from p12_deployment import load_configuration
from p12_binding import SCAFFOLD


class P12DeploymentTests(unittest.TestCase):
    def environment(self):
        return {key: 'test-' + key for key in (
            'GUIDED_CONTROL_VERIFIER_TOKEN', 'GUIDED_VERIFIER_LAB12_TOKEN',
            *('GUIDED_P12_' + name + '_VERIFIER_TOKEN' for name in ('CONTEXT', 'PRIVACY', 'NEMO', 'GATEWAY')))}

    def test_packaged_contract_and_scaffold_without_learner_hash(self):
        config = load_configuration(self.environment(), DIRECTORY)
        self.assertEqual(len(config['specifications']), 8)
        self.assertEqual(set(config['scaffold_files']), set(SCAFFOLD))
        self.assertNotIn('pipeline.py', config['scaffold_files'])
        self.assertEqual(set(config['tokens']), {'context', 'privacy', 'nemo', 'gateway'})

    def test_missing_or_shared_credentials_fail_locally(self):
        env = self.environment()
        for key in env:
            with self.subTest(key=key):
                missing = dict(env)
                del missing[key]
                with self.assertRaises(ValueError):
                    load_configuration(missing, DIRECTORY)
        env['GUIDED_P12_NEMO_VERIFIER_TOKEN'] = env['GUIDED_P12_CONTEXT_VERIFIER_TOKEN']
        with self.assertRaises(ValueError):
            load_configuration(env, DIRECTORY)

    def test_compose_assigns_roles_to_correct_services(self):
        services = yaml.safe_load((ROOT / 'examples/security-monitoring/compose.guided.yaml').read_text())['services']
        self.assertNotIn('guided-h12-stage-provider', services)
        verifier = services['guided-evidence-verifier']['environment']
        runner = services['guided-h12-application-pipeline']['environment']
        gateway = services['guided-bedrock-gateway']['environment']
        for name in ('CONTEXT', 'PRIVACY', 'NEMO', 'GATEWAY'):
            self.assertIn(f'GUIDED_P12_{name}_VERIFIER_TOKEN', verifier)
            self.assertNotIn(f'GUIDED_P12_{name}_CONTROL_TOKEN', verifier)
            self.assertNotIn(f'GUIDED_P12_{name}_SERVICE_TOKEN', verifier)
            self.assertIn(f'GUIDED_P12_{name}_CONTROL_TOKEN', runner)
            self.assertNotIn(f'GUIDED_P12_{name}_VERIFIER_TOKEN', runner)
        self.assertIn('GUIDED_P12_GATEWAY_CONTROL_TOKEN', gateway)
        self.assertIn('GUIDED_P12_GATEWAY_VERIFIER_TOKEN', gateway)
        self.assertEqual(gateway['GUIDED_P12_GATEWAY_DATABASE'], '/state/p12-gateway.sqlite3')
        self.assertFalse(services['guided-h12-application-pipeline'].get('depends_on'))

    def test_default_recipe_uses_packaged_factory_not_mock(self):
        recipe = (ROOT / 'llm-security-control-plane/guided-labs/h12-application-pipeline/Containerfile').read_text()
        self.assertIn('run_server:configured_app', recipe)
        self.assertIn('"--factory"', recipe)
        self.assertNotIn('h12-application-pipeline/server.py', recipe)

    def test_legacy_mock_and_answer_are_not_current_assets(self):
        control = ROOT / 'llm-security-control-plane'
        for name in ('guided-labs/h12-application-pipeline/server.py',
                     'guided-labs/h12-stage-provider/server.py',
                     'guided-labs/h12-stage-provider/Containerfile',
                     'guided-solutions/h12-application-pipeline/pipeline.py'):
            self.assertFalse((control / name).exists(), name)
        starter = (control / 'guided-labs/h12-application-pipeline/pipeline.py').read_text()
        self.assertNotIn('def stage_order', starter)
        self.assertNotIn('def may_continue', starter)
        self.assertIn('async def handle_request', starter)
        self.assertIn('raise NotImplementedError', starter)


if __name__ == '__main__':
    unittest.main()
