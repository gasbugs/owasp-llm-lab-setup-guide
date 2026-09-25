"""P04 provisioning SDK contracts and authenticated API; no live AWS writes."""
from copy import deepcopy
import hashlib
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

import botocore.session
from botocore.stub import Stubber
from fastapi.testclient import TestClient
from test_guided_p04_resource_contract import GATEWAY, fixture, metadata

sys.path.insert(0, str(GATEWAY))
try:
    import p04_provisioning as provisioning
    from p04_gateway import configured_app, load_cases
    from p04_preparation import PreparationStore
    from p04_contract import canonical
    from p04_ledger import LedgerError
finally:
    sys.path.remove(str(GATEWAY))

PROVISION, CONTROL, VERIFIER = 'provision-' * 8, 'control-' * 8, 'verifier-' * 8


def headers(token):
    return {'Authorization': 'Bearer ' + token}


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / 'gateway.sqlite3'
        self.store = PreparationStore(self.path)
        self.t, self.detail, self.tags, self.summary = fixture()
        self.clients, self.stubs, self.configs = {}, {}, []
        for name in ('sts', 'bedrock'):
            client = botocore.session.get_session().create_client(name, region_name='us-east-1',
                aws_access_key_id='test', aws_secret_access_key='test')
            self.addCleanup(client.close)
            self.clients[name] = client
            stub = Stubber(client)
            stub.activate()
            self.addCleanup(stub.deactivate)
            self.stubs[name] = stub
        self.manager = provisioning.Provisioner(self.store, client_factory=self.factory, sleep=lambda seconds: None)
        self.operation = str(uuid4())

    def factory(self, name, **kwargs):
        self.configs.append((name, kwargs))
        return self.clients[name]

    def identity(self):
        self.stubs['sts'].add_response('get_caller_identity', {'Account': '000000000000',
            'UserId': 'fixture', 'Arn': 'arn:aws:iam::000000000000:user/fixture', **metadata('identity')}, {})

    def existing(self, detail=None):
        stub = self.stubs['bedrock']
        stub.add_response('list_guardrails', {'guardrails': [self.summary], **metadata('list')}, {'maxResults': 100})
        stub.add_response('get_guardrail', {**(detail or self.detail), **metadata('get')},
                          {'guardrailIdentifier': 'p04test', 'guardrailVersion': 'DRAFT'})
        stub.add_response('list_tags_for_resource', {'tags': self.tags, **metadata('tags')},
                          {'resourceARN': self.detail['guardrailArn']})

    def no_pending(self):
        for stub in self.stubs.values():
            stub.assert_no_pending_responses()

    def test_existing_owned_policy_is_read_only_and_journaled(self):
        self.identity()
        self.existing()
        result = self.manager.prepare(self.operation)
        self.assertEqual(result['state'], 'ready')
        self.assertIs(result['evidence']['created'], False)
        self.assertEqual(len(result['evidence']['aws_request_ids']), 4)
        self.assertEqual(self.store.resources(), result['resources'])
        for name, args in self.configs:
            self.assertEqual(args['region_name'], 'us-east-1')
            self.assertEqual(args['config'].retries['total_max_attempts'], 1)
            self.assertEqual(args['config'].read_timeout, 10)
        self.no_pending()

    def test_absent_policy_is_created_once_then_reaudited(self):
        self.identity()
        stub = self.stubs['bedrock']
        stub.add_response('list_guardrails', {'guardrails': [], **metadata('list')}, {'maxResults': 100})
        expected = {'name': self.t['name'], 'description': self.t['description'], **self.t['policy'], 'tags': self.tags,
                    'clientRequestToken': hashlib.sha256(canonical({'name': self.t['name'],
                        'operation_id': self.operation,
                        'template_digest': self.t['template_digest']})).hexdigest()}
        stub.add_response('create_guardrail', {'guardrailId': 'p04test', 'guardrailArn': self.detail['guardrailArn'],
            'version': 'DRAFT', 'createdAt': self.detail['createdAt'], **metadata('create')}, expected)
        for status, request_id in (('CREATING', 'wait'), ('READY', 'ready')):
            stub.add_response('get_guardrail', {**self.detail, 'status': status, **metadata(request_id)},
                              {'guardrailIdentifier': 'p04test', 'guardrailVersion': 'DRAFT'})
        stub.add_response('list_tags_for_resource', {'tags': self.tags, **metadata('tags')},
                          {'resourceARN': self.detail['guardrailArn']})
        result = self.manager.prepare(self.operation)
        self.assertTrue(result['evidence']['created'])
        self.assertEqual(result['resources']['policy_digest'], self.t['template_digest'])
        self.assertEqual(len(result['evidence']['aws_request_ids']), 6)
        self.no_pending()

    def test_foreign_policy_never_repaired_or_created(self):
        self.identity()
        changed = deepcopy(self.detail)
        changed['sensitiveInformationPolicy']['piiEntities'][0]['outputEnabled'] = False
        self.existing(changed)
        with self.assertRaises(LedgerError):
            self.manager.prepare(self.operation)
        self.assertEqual(self.store.read(self.operation)['state'], 'error')
        with self.assertRaises(LedgerError):
            self.store.resources()
        self.no_pending()

    def test_identity_failure_invalidates_previous_ready_and_releases_lock(self):
        self.identity()
        self.existing()
        self.manager.prepare(self.operation)
        operation = str(uuid4())
        self.stubs['sts'].add_client_error('get_caller_identity', service_error_code='AccessDenied',
                                          service_message='private detail', expected_params={})
        with self.assertRaises(LedgerError) as caught:
            self.manager.prepare(operation)
        self.assertEqual(caught.exception.status, 502)
        self.assertEqual(self.store.read(operation)['state'], 'error')
        with self.assertRaises(LedgerError):
            self.store.resources()
        self.assertFalse(self.manager.lock.locked())
        self.no_pending()

    def test_duplicate_preparation_and_lock_do_not_call_aws(self):
        self.store.begin(self.operation, '000000000000')
        with self.assertRaises(LedgerError):
            self.manager.prepare(self.operation)
        self.assertEqual(self.configs, [])
        self.manager.lock.acquire()
        with self.assertRaises(LedgerError):
            self.manager.prepare(str(uuid4()))
        self.manager.lock.release()
        self.assertEqual(self.configs, [])

    def test_configured_api_authentication_startup_and_prepared_suite(self):
        with patch.object(provisioning.boto3, 'client', side_effect=self.factory):
            app = configured_app(self.path, provider_mode='aws', region='us-east-1',
                control_token=CONTROL, verifier_token=VERIFIER, provision_token=PROVISION)
        client = TestClient(app)
        self.addCleanup(client.close)
        self.assertEqual(client.get('/readyz').status_code, 200)
        self.assertEqual(self.configs, [])
        for credential in (CONTROL, VERIFIER, 'wrong'):
            self.assertEqual(client.post('/resources/prepare', json={'operation_id': self.operation},
                headers=headers(credential)).status_code, 401)
        for body in ({'operation_id': self.operation, 'policy': 'private-input'}, {'operation_id': 'bad'}):
            response = client.post('/resources/prepare', json=body, headers=headers(PROVISION))
            self.assertEqual(response.status_code, 422)
            self.assertNotIn('private-input', response.text)
        self.assertEqual(self.configs, [])
        self.identity()
        self.existing()
        response = client.post('/resources/prepare', json={'operation_id': self.operation}, headers=headers(PROVISION))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['state'], 'ready')
        self.assertNotIn('security_verdict', response.json())
        read_path = '/resources/preparations/' + self.operation
        self.assertEqual(client.get(read_path, headers=headers(PROVISION)).status_code, 401)
        self.assertEqual(client.get(read_path, headers=headers(VERIFIER)).json(), response.json())
        suite = str(uuid4())
        rows = [{'case_id': case['case_id'], 'execution_id': str(uuid4())} for case in load_cases()]
        registered = client.post('/suites', json={'suite_id': suite, 'cases': rows}, headers=headers(CONTROL))
        self.assertEqual(registered.status_code, 200)
        registered = client.get('/suites/' + suite, headers=headers(VERIFIER)).json()
        self.assertEqual(registered['resources'], response.json()['resources'])
        self.no_pending()

    def test_contract_mode_does_not_provision_aws(self):
        with patch.object(provisioning.boto3, 'client', side_effect=AssertionError('unexpected AWS')):
            app = configured_app(self.path, provider_mode='contract', region='us-east-1',
                control_token=CONTROL, verifier_token=VERIFIER, provision_token=PROVISION)
            with TestClient(app) as client:
                result = client.post('/resources/prepare', json={'operation_id': self.operation}, headers=headers(PROVISION))
                self.assertEqual(result.status_code, 503)
                self.assertEqual(client.get('/readyz').status_code, 200)

    def test_failed_or_never_ready_creation_is_not_retried_or_published(self):
        for status, expected_calls in (('FAILED', 1), ('CREATING', 40)):
            with self.subTest(status=status):
                sts, bedrock = Mock(), Mock()
                bedrock.meta.region_name = 'us-east-1'
                sts.get_caller_identity.return_value = {'Account': '000000000000', **metadata('identity')}
                bedrock.list_guardrails.return_value = {'guardrails': [], **metadata('list')}
                bedrock.create_guardrail.return_value = {'guardrailId': 'p04test',
                    'guardrailArn': self.detail['guardrailArn'], 'version': 'DRAFT', **metadata('create')}
                bedrock.get_guardrail.side_effect = lambda **kw: {
                    **self.detail, 'status': status, **metadata('wait-' + str(bedrock.get_guardrail.call_count))}
                manager = provisioning.Provisioner(self.store,
                    client_factory=lambda service, **kwargs: sts if service == 'sts' else bedrock,
                    sleep=lambda seconds: None)
                operation = str(uuid4())
                with self.assertRaises(LedgerError):
                    manager.prepare(operation)
                self.assertEqual(self.store.read(operation)['state'], 'error')
                with self.assertRaises(LedgerError):
                    self.store.resources()
                self.assertEqual(bedrock.create_guardrail.call_count, 1)
                self.assertEqual(bedrock.get_guardrail.call_count, expected_calls)
                bedrock.update_guardrail.assert_not_called()
                bedrock.delete_guardrail.assert_not_called()
                sts.close.assert_called_once()
                bedrock.close.assert_called_once()
                self.assertFalse(manager.lock.locked())


if __name__ == '__main__':
    unittest.main()
