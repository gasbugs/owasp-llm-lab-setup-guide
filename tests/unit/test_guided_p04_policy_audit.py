"""Current AWS policy inspection with SDK fixtures, not live AWS evidence."""
from copy import deepcopy
import sys
import unittest
from unittest.mock import Mock

import botocore.session
from botocore.stub import Stubber
from test_guided_p04_resource_contract import GATEWAY, fixture, metadata, validate_owned, LedgerError

sys.path.insert(0, str(GATEWAY))
try:
    from p04_policy_audit import PolicyAudit
finally:
    sys.path.remove(str(GATEWAY))


class PolicyAuditTests(unittest.TestCase):
    def setUp(self):
        t, self.detail, self.tags, _ = fixture()
        self.resources = validate_owned(t, self.detail, self.tags, expected_id='p04test')
        self.clients, self.stubs, self.requests = {}, {}, []
        for name in ('sts', 'bedrock'):
            client = botocore.session.get_session().create_client(name, region_name='us-east-1',
                aws_access_key_id='test', aws_secret_access_key='test')
            self.clients[name] = client
            self.addCleanup(client.close)
            stub = Stubber(client)
            stub.activate()
            self.stubs[name] = stub
            self.addCleanup(stub.deactivate)

    def factory(self, name, **kwargs):
        self.requests.append((name, kwargs))
        return self.clients[name]

    def identity(self, account='000000000000'):
        self.stubs['sts'].add_response('get_caller_identity', {'Account': account, 'UserId': 'fixture',
            'Arn': 'arn:aws:iam::' + account + ':user/fixture', **metadata('identity')}, {})

    def policy(self, detail=None, tags=None):
        self.stubs['bedrock'].add_response('get_guardrail', {**(detail or self.detail), **metadata('policy')}, self.resources['guardrail'])
        self.stubs['bedrock'].add_response('list_tags_for_resource', {'tags': self.tags if tags is None else tags,
            **metadata('tags')}, {'resourceARN': self.resources['guardrail_arn']})

    def audit(self):
        return PolicyAudit(client_factory=self.factory, now=Mock(side_effect=[1000, 1001]))(self.resources)

    def test_fresh_native_policy_and_identity_are_bounded_and_read_only(self):
        self.identity()
        self.policy()
        result = self.audit()
        self.assertEqual(result, {'scope': 'aws-policy-audit', 'started_at': 1000, 'observed_at': 1001,
            'resources': self.resources, 'aws_request_ids': ['p04-audit-identity', 'p04-audit-policy', 'p04-audit-tags']})
        for stub in self.stubs.values():
            stub.assert_no_pending_responses()
        for _, kwargs in self.requests:
            self.assertEqual(kwargs['region_name'], 'us-east-1')
            self.assertEqual(kwargs['config'].retries['total_max_attempts'], 1)
            self.assertEqual(kwargs['config'].read_timeout, 3)

    def test_policy_changed_after_preparation_is_not_current(self):
        self.identity()
        changed = deepcopy(self.detail)
        changed['sensitiveInformationPolicy']['piiEntities'][0]['outputEnabled'] = False
        self.policy(changed)
        with self.assertRaises(LedgerError):
            self.audit()

    def test_removed_ownership_tag_is_not_current(self):
        self.identity()
        self.policy(tags=[])
        with self.assertRaises(LedgerError):
            self.audit()

    def test_switched_aws_account_stops_before_guardrail_read(self):
        self.identity('111111111111')
        with self.assertRaises(LedgerError):
            self.audit()
        self.assertEqual([name for name, _ in self.requests], ['sts'])

    def test_timeout_prevents_sdk_and_contract_snapshot_is_not_audited(self):
        factory = Mock(side_effect=AssertionError('unexpected SDK'))
        audit = PolicyAudit(client_factory=factory, clock=Mock(side_effect=[0, 13]))
        with self.assertRaises(LedgerError):
            audit(self.resources)
        factory.assert_not_called()
        contract = {'provider_mode': 'contract', 'guardrail': {'guardrailIdentifier': 'p04contract', 'guardrailVersion': 'DRAFT'},
                    'guardrail_arn': None, 'policy_digest': 'a' * 64}
        with self.assertRaises(LedgerError):
            PolicyAudit(client_factory=factory)(contract)
        factory.assert_not_called()

    def test_sdk_error_is_not_success_and_private_error_is_not_exposed(self):
        self.stubs['sts'].add_client_error('get_caller_identity', service_error_code='AccessDenied',
            service_message='private credential context', expected_params={})
        with self.assertRaises(LedgerError) as caught:
            self.audit()
        self.assertEqual(caught.exception.status, 502)
        self.assertNotIn('private credential context', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
