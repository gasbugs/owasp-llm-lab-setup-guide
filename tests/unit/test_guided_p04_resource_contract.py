"""P04 resource reuse rejects foreign/changed policies; all AWS responses are fixtures."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

import botocore.session
from botocore.stub import Stubber
from botocore.validate import validate_parameters

GATEWAY = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-bedrock-gateway'
sys.path.insert(0, str(GATEWAY))
try:
    from p04_resource_contract import template, validate_owned, inspect_existing
    from p04_ledger import LedgerError
finally:
    sys.path.remove(str(GATEWAY))


def fixture():
    t = template('000000000000')
    arn = 'arn:aws:bedrock:us-east-1:000000000000:guardrail/p04test'
    now = datetime(2026, 9, 25, tzinfo=timezone.utc)
    detail = {'name': t['name'], 'description': t['description'], 'guardrailId': 'p04test',
              'guardrailArn': arn, 'version': 'DRAFT', 'status': 'READY', 'createdAt': now, 'updatedAt': now,
              'sensitiveInformationPolicy': {'piiEntities': deepcopy(t['policy']['sensitiveInformationPolicyConfig']['piiEntitiesConfig']),
                                             'regexes': []},
              'blockedInputMessaging': t['policy']['blockedInputMessaging'],
              'blockedOutputsMessaging': t['policy']['blockedOutputsMessaging']}
    tags = [{'key': key, 'value': value} for key, value in t['tags'].items()]
    summary = {'name': t['name'], 'id': 'p04test', 'arn': arn, 'version': 'DRAFT',
               'status': 'READY', 'createdAt': now, 'updatedAt': now}
    return t, detail, tags, summary


def metadata(index):
    return {'ResponseMetadata': {'HTTPStatusCode': 200, 'RequestId': 'p04-audit-' + str(index)}}


class ResourceContractTests(unittest.TestCase):
    def setUp(self):
        self.t, self.detail, self.tags, self.summary = fixture()
        self.client = botocore.session.get_session().create_client('bedrock', region_name='us-east-1',
            aws_access_key_id='test', aws_secret_access_key='test')
        self.addCleanup(self.client.close)

    def audit(self, **kwargs):
        return validate_owned(kwargs.get('specification', self.t), kwargs.get('detail', self.detail),
                              kwargs.get('tags', self.tags), expected_id=kwargs.get('expected_id', 'p04test'))

    def test_template_is_account_scoped_not_h04_and_sdk_create_shape_is_valid(self):
        self.assertIn('p04', self.t['name'])
        self.assertNotIn('h04', self.t['name'])
        validate_parameters({'name': self.t['name'], 'description': self.t['description'],
                             **self.t['policy'], 'tags': self.tags, 'clientRequestToken': 'a' * 64},
                            self.client.meta.service_model.operation_model('CreateGuardrail').input_shape)
        for account, region in (('bad', 'us-east-1'), (0, 'us-east-1'), ('000000000000', 'us-west-2')):
            with self.assertRaises(ValueError):
                template(account, region)
        self.t['policy']['sensitiveInformationPolicyConfig']['piiEntitiesConfig'][0]['outputEnabled'] = False
        with self.assertRaises(LedgerError):
            self.audit()

    def test_exact_email_policy_has_stable_snapshot(self):
        snapshot = self.audit()
        self.assertEqual(snapshot['policy_digest'], self.t['template_digest'])
        self.assertEqual(snapshot['guardrail'], {'guardrailIdentifier': 'p04test', 'guardrailVersion': 'DRAFT'})
        self.assertEqual(snapshot['provider_mode'], 'aws')
        self.detail['wordPolicy'] = {'words': [], 'managedWordLists': []}
        self.assertEqual(snapshot, self.audit())

    def test_modified_template_boolean_is_not_equivalent_to_zero(self):
        altered = deepcopy(self.t)
        altered['policy']['sensitiveInformationPolicyConfig']['piiEntitiesConfig'][0]['inputEnabled'] = 0
        with self.assertRaises(LedgerError):
            self.audit(specification=altered)
        client = Mock()
        client.meta.region_name = 'us-east-1'
        with self.assertRaises(LedgerError):
            inspect_existing(altered, client=client)
        client.list_guardrails.assert_not_called()

    def test_every_identity_and_lifecycle_field_must_match(self):
        for field, value in (('name', 'owasp-llm-03-h04-000000000000'), ('description', 'foreign'),
                             ('guardrailId', 'other'), ('guardrailArn', self.detail['guardrailArn'].replace('000000000000', '111111111111')),
                             ('version', '1'), ('status', 'UPDATING'), ('blockedInputMessaging', 'other'),
                             ('blockedOutputsMessaging', 'other')):
            with self.subTest(field=field), self.assertRaises(LedgerError):
                self.audit(detail={**self.detail, field: value})
        for value in ('../../foreign', None, True, 'p04-test'):
            with self.assertRaises(LedgerError):
                self.audit(expected_id=value)

    def test_missing_foreign_and_duplicate_ownership_tags_are_rejected(self):
        for tags in ([], self.tags[:-1], self.tags + [self.tags[0]],
                     [{**row, 'value': 'H04'} if row['key'] == 'Activity' else row for row in self.tags],
                     None, [{'key': 'Course'}]):
            with self.subTest(tags=tags), self.assertRaises(LedgerError):
                self.audit(tags=tags)

    def test_each_email_field_and_integer_boolean_confusion_is_rejected(self):
        for field, value in (('type', 'PHONE'), ('action', 'BLOCK'), ('inputAction', 'BLOCK'),
                             ('outputAction', 'NONE'), ('inputEnabled', True), ('outputEnabled', False),
                             ('inputEnabled', 0), ('outputEnabled', 1)):
            detail = deepcopy(self.detail)
            detail['sensitiveInformationPolicy']['piiEntities'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(LedgerError):
                self.audit(detail=detail)

    def test_extra_pii_regex_and_unreviewed_policy_fields_are_rejected(self):
        for extra in ({'regexes': [{'name': 'hidden'}]}, {'extra': {}}, {'piiEntities': []},
                      {'piiEntities': self.detail['sensitiveInformationPolicy']['piiEntities'] * 2}):
            detail = deepcopy(self.detail)
            detail['sensitiveInformationPolicy'].update(extra)
            with self.assertRaises(LedgerError):
                self.audit(detail=detail)
        for field, value in (('topicPolicy', {'topics': [{'name': 'deny'}]}),
                             ('contentPolicy', {'filters': [{'type': 'HATE'}]}),
                             ('wordPolicy', {'words': [{'text': 'hello'}]}),
                             ('contextualGroundingPolicy', {'filters': [{'type': 'GROUNDING'}]}),
                             ('automatedReasoningPolicy', {'policies': ['foreign']}),
                             ('crossRegionDetails', {'guardrailProfileId': 'other'}),
                             ('kmsKeyArn', 'foreign'), ('newPolicy', {}), ('statusReasons', ['failed'])):
            with self.subTest(field=field), self.assertRaises(LedgerError):
                self.audit(detail={**self.detail, field: value})

    def test_paginated_sdk_read_only_reuse_is_audited(self):
        with Stubber(self.client) as stub:
            stub.add_response('list_guardrails', {'guardrails': [], 'nextToken': 'page2', **metadata(1)}, {'maxResults': 100})
            stub.add_response('list_guardrails', {'guardrails': [self.summary], **metadata(2)}, {'maxResults': 100, 'nextToken': 'page2'})
            stub.add_response('get_guardrail', {**self.detail, **metadata(3)},
                              {'guardrailIdentifier': 'p04test', 'guardrailVersion': 'DRAFT'})
            stub.add_response('list_tags_for_resource', {'tags': self.tags, **metadata(4)},
                              {'resourceARN': self.detail['guardrailArn']})
            result = inspect_existing(self.t, client=self.client)
            self.assertEqual(result['state'], 'ready')
            self.assertEqual(result['resources'], self.audit())
            self.assertEqual(len(result['aws_request_ids']), 4)
            stub.assert_no_pending_responses()

    def test_absence_is_not_ready_and_other_names_do_not_match(self):
        with Stubber(self.client) as stub:
            summary = {**self.summary, 'name': 'owasp-llm-03-h04-000000000000'}
            stub.add_response('list_guardrails', {'guardrails': [summary], **metadata(1)}, {'maxResults': 100})
            result = inspect_existing(self.t, client=self.client)
            self.assertEqual(result, {'state': 'absent', 'resources': None, 'aws_request_ids': ['p04-audit-1']})
            stub.assert_no_pending_responses()

    def test_duplicate_names_and_wrong_account_stop_before_get(self):
        for summaries in ([self.summary, self.summary], [{**self.summary, 'arn': self.detail['guardrailArn'].replace('000000000000', '111111111111')} ]):
            with Stubber(self.client) as stub:
                stub.add_response('list_guardrails', {'guardrails': summaries, **metadata(1)}, {'maxResults': 100})
                with self.assertRaises(LedgerError):
                    inspect_existing(self.t, client=self.client)
                stub.assert_no_pending_responses()

    def test_read_errors_are_not_absence(self):
        with Stubber(self.client) as stub:
            stub.add_client_error('list_guardrails', service_error_code='AccessDeniedException',
                                  expected_params={'maxResults': 100})
            with self.assertRaises(self.client.exceptions.AccessDeniedException):
                inspect_existing(self.t, client=self.client)

    def test_repeated_page_token_request_id_and_timeout_are_rejected(self):
        client = Mock()
        client.meta.region_name = 'us-east-1'
        client.list_guardrails.side_effect = [
            {'guardrails': [], 'nextToken': 'same', **metadata(1)},
            {'guardrails': [], 'nextToken': 'same', **metadata(2)}]
        with self.assertRaises(LedgerError):
            inspect_existing(self.t, client=client)
        self.assertEqual(client.list_guardrails.call_count, 2)
        client.list_guardrails.side_effect = [
            {'guardrails': [], 'nextToken': 'next', **metadata(1)}, {'guardrails': [], **metadata(1)}]
        with self.assertRaises(LedgerError):
            inspect_existing(self.t, client=client)
        client.list_guardrails.reset_mock()
        with self.assertRaises(LedgerError):
            inspect_existing(self.t, client=client, clock=Mock(side_effect=[0, 61]))
        client.list_guardrails.assert_not_called()


if __name__ == '__main__':
    unittest.main()
