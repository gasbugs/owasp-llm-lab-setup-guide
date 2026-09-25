"""Real SDK schemas, stubbed AWS: strict publisher deletion scope."""
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

import botocore.session
from botocore.stub import Stubber
import test_guided_p04_resource_contract as resources
import test_guided_p04_cleanup_proof as local_proof

ROOT = Path(__file__).resolve().parents[2]
with patch.object(sys, 'path', [str(ROOT / 'tests/e2e'), str(resources.GATEWAY), *sys.path]):
    from p04_aws_cleanup import cleanup_created


class AwsCleanupTests(unittest.TestCase):
    def setUp(self):
        local_proof.CleanupProofTests.setUp(self)
        _, self.detail, self.tags, self.summary = resources.fixture()
        timestamp = datetime.fromtimestamp(1012, timezone.utc)
        for item in (self.detail, self.summary):
            item.update(createdAt=timestamp, updatedAt=timestamp)
        session = botocore.session.get_session()
        self.sdk = {name: session.create_client(name, region_name='us-east-1',
            aws_access_key_id='test', aws_secret_access_key='test') for name in ('sts', 'bedrock')}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for sdk in self.sdk.values():
            self.addCleanup(sdk.close)
        self.stubs = {name: self.stack.enter_context(Stubber(sdk)) for name, sdk in self.sdk.items()}
        self.factory = Mock(side_effect=lambda service, **kwargs: self.sdk[service])
        self.params = {'guardrailIdentifier': 'p04test', 'guardrailVersion': 'DRAFT'}

    def run_cleanup(self):
        return cleanup_created(self.preflight, self.prepared, self.path,
            client_factory=self.factory, now=lambda: 1030, sleep=lambda _: None)

    def reads(self, *, account='000000000000', versions=None, extra=None):
        self.stubs['sts'].add_response('get_caller_identity', {'Account': account,
            'Arn': 'arn:aws:iam::000000000000:user/test', 'UserId': 'test', **resources.metadata(1)}, {})
        if account != '000000000000':
            return
        stub = self.stubs['bedrock']
        stub.add_response('get_guardrail', {**self.detail, **resources.metadata(2)}, self.params)
        stub.add_response('list_tags_for_resource', {'tags': self.tags, **resources.metadata(3)},
            {'resourceARN': self.detail['guardrailArn']})
        if versions is not False:
            stub.add_response('list_guardrails', {'guardrails': versions if versions is not None else [self.summary],
                **resources.metadata(4), **(extra or {})}, {'guardrailIdentifier': 'p04test', 'maxResults': 100})

    def test_exact_id_single_delete_and_confirmed_absence(self):
        self.reads()
        stub = self.stubs['bedrock']
        stub.add_response('delete_guardrail', resources.metadata(5), {'guardrailIdentifier': 'p04test'})
        stub.add_client_error('get_guardrail', service_error_code='ResourceNotFoundException',
            http_status_code=404, response_meta={'RequestId': 'not-found'}, expected_params=self.params)
        result = self.run_cleanup()
        self.assertTrue(result['resources_absent'])
        self.assertEqual(result['guardrail_id'], 'p04test')
        self.assertEqual(len(result['aws_request_ids']), 6)
        stub.assert_no_pending_responses()
        for call in self.factory.call_args_list:
            self.assertEqual(call.kwargs['config'].retries['total_max_attempts'], 1)

    def test_wrong_account_never_opens_bedrock(self):
        self.reads(account='111111111111')
        with self.assertRaises(ValueError):
            self.run_cleanup()
        self.assertEqual([call.args[0] for call in self.factory.call_args_list], ['sts'])

    def test_extra_tags_never_delete(self):
        self.tags.append({'key': 'Owner', 'value': 'someone-else'})
        self.reads(versions=False)
        with self.assertRaises(ValueError):
            self.run_cleanup()
        self.stubs['bedrock'].assert_no_pending_responses()

    def test_changed_policy_never_deletes(self):
        self.detail['blockedOutputsMessaging'] = 'changed'
        self.reads(versions=False)
        with self.assertRaises(resources.LedgerError):
            self.run_cleanup()
        self.stubs['bedrock'].assert_no_pending_responses()

    def test_old_creation_time_never_deletes(self):
        self.detail['createdAt'] = datetime.fromtimestamp(500, timezone.utc)
        self.reads(versions=False)
        with self.assertRaises(ValueError):
            self.run_cleanup()
        self.stubs['bedrock'].assert_no_pending_responses()

    def test_published_version_is_not_owned_test_state(self):
        self.reads(versions=[self.summary, {**self.summary, 'version': '1'}])
        with self.assertRaises(ValueError):
            self.run_cleanup()
        self.stubs['bedrock'].assert_no_pending_responses()

    def test_paginated_versions_are_not_safe_to_delete(self):
        self.reads(extra={'nextToken': 'another-page'})
        with self.assertRaises(ValueError):
            self.run_cleanup()
        self.stubs['bedrock'].assert_no_pending_responses()

    def test_reused_resources_stop_before_any_sdk_client(self):
        self.prepared['evidence']['created'] = False
        with self.assertRaises(ValueError):
            self.run_cleanup()
        self.factory.assert_not_called()

    def test_access_denied_after_delete_is_not_absence(self):
        self.reads()
        stub = self.stubs['bedrock']
        stub.add_response('delete_guardrail', resources.metadata(5), {'guardrailIdentifier': 'p04test'})
        stub.add_client_error('get_guardrail', service_error_code='AccessDeniedException',
            http_status_code=403, expected_params=self.params)
        with self.assertRaises(ValueError):
            self.run_cleanup()
        stub.assert_no_pending_responses()


if __name__ == '__main__':
    unittest.main()
