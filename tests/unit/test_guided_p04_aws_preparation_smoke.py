"""Publisher orchestration tests: mocks only, no cloud credentials or network."""
from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_guided_p04_product as product
import test_guided_p04_resource_contract as resources

ROOT = Path(__file__).resolve().parents[2]
with patch.object(sys, 'path', [str(ROOT / 'tests/e2e'), str(resources.GATEWAY),
        str(ROOT / 'llm-security-control-plane/guided-evidence-verifier'), *sys.path]), \
        patch.dict(sys.modules, {'cases': product.case_module}):
    spec = importlib.util.spec_from_file_location('p04_publisher_smoke', ROOT / 'tests/e2e/check_guided_p04_aws_preparation.py')
    publisher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(publisher)


class PublisherSmokeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name) / 'proof'
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.before = {'resources_absent': True}
        self.prepared = {'resources': {'guardrail': product.GUARDRAIL}}
        self.preflight = self.stack.enter_context(patch.object(publisher, 'preflight', return_value=self.before))
        self.provisioner = self.stack.enter_context(patch.object(publisher, 'Provisioner'))
        self.provisioner.return_value.prepare.return_value = self.prepared
        self.cleanup = self.stack.enter_context(patch.object(publisher, 'cleanup_created', return_value={'resources_absent': True}))
        self.sdk = self.stack.enter_context(patch.object(publisher.boto3, 'client', side_effect=AssertionError('unexpected AWS call')))
        audit = self.stack.enter_context(patch.object(publisher, 'PolicyAudit'))
        audit.return_value.return_value = {'scope': 'fixture only'}
        responses = [product.response_for(case) for case in product.case_module.cases()[:4]]
        backend = self.stack.enter_context(patch.object(publisher, 'BedrockBackend'))
        backend.return_value = Mock(side_effect=responses)

    def result(self):
        return json.loads((self.output / 'result.json').read_text())

    def test_success_retains_four_raw_responses_and_cleans_once(self):
        result = publisher.run('000000000000', self.output)
        self.assertTrue(result['checked'])
        self.assertEqual(len(result['cases']), 4)
        self.assertEqual(len(list(self.output.glob('*-response.json'))), 4)
        self.cleanup.assert_called_once()
        self.assertEqual(self.cleanup.call_args.args[:2], (self.before, self.prepared))
        self.sdk.assert_not_called()

    def test_product_failure_preserves_raw_and_still_cleans_created_resource(self):
        with patch.object(publisher, 'verify_product_response', side_effect=ValueError('fixture failure')):
            with self.assertRaises(ValueError):
                publisher.run('000000000000', self.output)
        self.assertFalse(self.result()['checked'])
        self.assertTrue((self.output / 'apply_guardrail-normal-response.json').exists())
        self.cleanup.assert_called_once()

    def test_partial_preparation_never_calls_cleanup(self):
        self.provisioner.return_value.prepare.side_effect = ValueError('partial')
        with self.assertRaises(ValueError):
            publisher.run('000000000000', self.output)
        self.cleanup.assert_not_called()
        self.assertEqual(self.result()['error_type'], 'ValueError')

    def test_cleanup_error_is_not_reported_as_absence(self):
        self.cleanup.side_effect = ValueError('not owned')
        with self.assertRaises(ValueError):
            publisher.run('000000000000', self.output)
        self.assertEqual(self.result()['cleanup_error_type'], 'ValueError')
        self.assertNotIn('cleanup', self.result())

    def test_existing_evidence_is_not_overwritten(self):
        self.output.mkdir()
        with self.assertRaises(FileExistsError):
            publisher.run('000000000000', self.output)
        self.preflight.assert_not_called()


if __name__ == '__main__':
    unittest.main()
