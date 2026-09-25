"""P04 publisher preflight with real SDK schemas and stubbed responses only."""
from contextlib import ExitStack
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

import botocore.session
from botocore.stub import Stubber
import test_guided_p04_resource_contract as resources

ROOT = Path(__file__).resolve().parents[2]
with patch.object(sys, 'path', [str(ROOT / 'tests/e2e'), str(resources.GATEWAY), *sys.path]):
    import p04_aws_scope as scope


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.account = '000000000000'
        session = botocore.session.get_session()
        self.sdk = {name: session.create_client(name, region_name='us-east-1',
            aws_access_key_id='test', aws_secret_access_key='test') for name in ('sts', 'bedrock')}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.closed = {}
        for name, sdk in self.sdk.items():
            self.addCleanup(sdk.close)
            self.closed[name] = self.stack.enter_context(patch.object(sdk, 'close', wraps=sdk.close))
        self.stubs = {name: self.stack.enter_context(Stubber(sdk)) for name, sdk in self.sdk.items()}
        self.factory = Mock(side_effect=lambda service, **_kwargs: self.sdk[service])

    def identity(self, account=None, request_id='identity-request'):
        self.stubs['sts'].add_response('get_caller_identity', {
            'Account': account or self.account, 'Arn': 'arn:aws:iam::000000000000:user/test',
            'UserId': 'test', 'ResponseMetadata': {'HTTPStatusCode': 200, 'RequestId': request_id}}, {})

    def run_preflight(self, **kwargs):
        return scope.preflight(self.account, client_factory=self.factory, now=Mock(side_effect=[1000, 1001]), **kwargs)

    def test_empty_pages_have_real_native_ids_and_clients_close(self):
        self.identity()
        self.stubs['bedrock'].add_response('list_guardrails', {'guardrails': [], 'nextToken': 'page2',
            **resources.metadata(1)}, {'maxResults': 100})
        self.stubs['bedrock'].add_response('list_guardrails', {'guardrails': [], **resources.metadata(2)},
            {'maxResults': 100, 'nextToken': 'page2'})
        result = self.run_preflight()
        self.assertTrue(result['resources_absent'])
        self.assertEqual(result['aws_request_ids'], ['identity-request', 'p04-audit-1', 'p04-audit-2'])
        self.assertEqual(len(result['responses']), 3)
        self.assertIn('no creation or cleanup authorization', result['scope'])
        for mock in self.closed.values():
            mock.assert_called_once()
        for call in self.factory.call_args_list:
            self.assertEqual(call.kwargs['region_name'], 'us-east-1')
            self.assertEqual(call.kwargs['config'].retries['total_max_attempts'], 1)

    def test_existing_owned_policy_is_not_an_absent_test_namespace(self):
        self.identity()
        _, detail, tags, summary = resources.fixture()
        stub = self.stubs['bedrock']
        stub.add_response('list_guardrails', {'guardrails': [summary], **resources.metadata(1)}, {'maxResults': 100})
        stub.add_response('get_guardrail', {**detail, **resources.metadata(2)},
            {'guardrailIdentifier': 'p04test', 'guardrailVersion': 'DRAFT'})
        stub.add_response('list_tags_for_resource', {'tags': tags, **resources.metadata(3)},
            {'resourceARN': detail['guardrailArn']})
        with self.assertRaises(ValueError):
            self.run_preflight()
        stub.assert_no_pending_responses()

    def test_wrong_account_stops_before_bedrock(self):
        self.identity(account='111111111111')
        with self.assertRaises(ValueError):
            self.run_preflight()
        self.assertEqual([call.args[0] for call in self.factory.call_args_list], ['sts'])
        self.closed['sts'].assert_called_once()

    def test_access_error_is_not_absence_and_private_error_is_not_reported(self):
        self.identity()
        self.stubs['bedrock'].add_client_error('list_guardrails', service_error_code='AccessDeniedException',
            service_message='private-marker', expected_params={'maxResults': 100})
        with self.assertRaises(ValueError) as caught:
            self.run_preflight()
        self.assertNotIn('private-marker', str(caught.exception))
        self.closed['bedrock'].assert_called_once()

    def test_invalid_account_and_expired_budget_do_not_create_clients(self):
        with self.assertRaises(ValueError):
            scope.preflight('invalid', client_factory=self.factory)
        with self.assertRaises(ValueError):
            self.run_preflight(clock=Mock(side_effect=[0, 91]))
        self.factory.assert_not_called()

    def test_duplicate_native_request_id_across_services_is_rejected(self):
        self.identity(request_id='p04-audit-1')
        self.stubs['bedrock'].add_response('list_guardrails', {'guardrails': [], **resources.metadata(1)}, {'maxResults': 100})
        with self.assertRaises(ValueError):
            self.run_preflight()

    def test_write_and_model_operations_are_rejected_before_call(self):
        guard = scope.ReadOnlyCalls()
        for operation in ('CreateGuardrail', 'DeleteGuardrail', 'UpdateGuardrail', 'Converse', 'ApplyGuardrail'):
            model = self.sdk['bedrock'].meta.service_model.operation_model(operation) if 'Guardrail' in operation and operation != 'ApplyGuardrail' else Mock(name='model')
            if operation in ('Converse', 'ApplyGuardrail'):
                model.name = operation
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                guard.before(model)
        self.assertEqual(guard.attempted, [])

    def test_sdk_event_guard_blocks_create_before_network(self):
        client = botocore.session.get_session().create_client('bedrock', region_name='us-east-1',
            aws_access_key_id='test', aws_secret_access_key='test')
        self.addCleanup(client.close)
        scope.ReadOnlyCalls().attach(client)
        with patch.object(client._endpoint, 'make_request') as send:
            with self.assertRaises(ValueError):
                client.create_guardrail(name='never-create', blockedInputMessaging='blocked', blockedOutputsMessaging='blocked')
        send.assert_not_called()


if __name__ == '__main__':
    unittest.main()
