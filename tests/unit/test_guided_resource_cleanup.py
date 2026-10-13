"""Deletion boundary tests use SDK mocks; never delete learner AWS resources."""
import importlib.util
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock

from botocore.exceptions import ClientError
from fastapi import HTTPException

path = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-bedrock-gateway/resource_cleanup.py'
sys.path.insert(0, str(path.parent))
spec = importlib.util.spec_from_file_location('resource_cleanup_unit', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def absent():
    return ClientError({'Error': {'Code': 'ResourceNotFoundException'}}, 'Get')


class CleanupBoundary(unittest.TestCase):
    def setUp(self):
        self.t = dict(source_bucket='owned-source', account_id='123456789012', vector_bucket='owned-vectors',
                      vector_index='knowledge', index_arn='owned-index', role_name='owned-role',
                      policy_name='owned-policy', knowledge_base_name='owned-kb', source_prefix='p03/knowledge/')
        self.state = dict(knowledge_base_id='owned-kb-id', data_source_id='owned-ds-id')
        self.sdk = {key: Mock() for key in ('s3', 'vectors', 'iam', 'agent')}
        self.sdk['s3'].get_bucket_versioning.return_value = {}
        self.sdk['s3'].get_paginator.return_value.paginate.return_value = [{'Contents': [{'Key': 'p03/knowledge/current-policy.md'}]}]
        self.sdk['vectors'].list_indexes.return_value = {'indexes': [{'indexName': 'knowledge'}]}
        self.sdk['agent'].list_ingestion_jobs.return_value = {'ingestionJobSummaries': [{'status': 'COMPLETE'}]}
        for key, method in [('s3', 'head_bucket'), ('vectors', 'get_index'), ('vectors', 'get_vector_bucket'),
                            ('agent', 'get_data_source'), ('agent', 'get_knowledge_base'), ('iam', 'get_role')]:
            getattr(self.sdk[key], method).side_effect = absent()

    def run_cleanup(self, audit=None):
        return module.cleanup_storage(self.t, audit or Mock(side_effect=[self.state, self.state, None]),
                                      self.sdk, problem='P03', sleep=lambda _: None)

    def no_deletes(self):
        self.assertFalse(any('delete_' in str(call) for client in self.sdk.values() for call in client.mock_calls))

    def test_exact_owned_resources_are_removed_and_absence_checked(self):
        self.assertEqual(len(self.run_cleanup()), 4)
        self.sdk['s3'].delete_bucket.assert_called_once_with(Bucket='owned-source', ExpectedBucketOwner='123456789012')
        self.sdk['vectors'].delete_index.assert_called_once_with(indexArn='owned-index')
        self.sdk['agent'].delete_data_source.assert_called_once_with(knowledgeBaseId='owned-kb-id', dataSourceId='owned-ds-id')

    def test_foreign_object_stops_before_any_delete(self):
        self.sdk['s3'].get_paginator.return_value.paginate.return_value = [{'Contents': [{'Key': 'another-course.md'}]}]
        with self.assertRaises(HTTPException): self.run_cleanup()
        self.no_deletes()

    def test_additional_index_stops_before_any_delete(self):
        self.sdk['vectors'].list_indexes.return_value['indexes'].append({'indexName': 'foreign'})
        with self.assertRaises(HTTPException): self.run_cleanup()
        self.no_deletes()

    def test_running_ingestion_stops_before_any_delete(self):
        self.sdk['agent'].list_ingestion_jobs.return_value = {'ingestionJobSummaries': [{'status': 'IN_PROGRESS'}]}
        with self.assertRaises(HTTPException): self.run_cleanup()
        self.no_deletes()

    def test_changed_ownership_audit_stops_before_any_delete(self):
        with self.assertRaises(HTTPException): self.run_cleanup(Mock(side_effect=[self.state, {'knowledge_base_id': 'changed'}]))
        self.no_deletes()

    def test_failed_ownership_audit_stops_before_any_delete(self):
        with self.assertRaises(HTTPException): self.run_cleanup(Mock(side_effect=HTTPException(409, 'ownership differs')))
        self.no_deletes()

    def test_versioned_bucket_is_not_deleted(self):
        self.sdk['s3'].get_bucket_versioning.return_value = {'Status': 'Enabled'}
        with self.assertRaises(HTTPException): self.run_cleanup()
        self.no_deletes()

    def test_absent_namespace_is_noop(self):
        self.assertEqual(self.run_cleanup(Mock(return_value=None)), [])
        self.no_deletes()

    def test_timeout_is_not_reported_as_deleted(self):
        self.sdk['agent'].get_data_source.side_effect = None
        self.sdk['agent'].get_data_source.return_value = {}
        with self.assertRaises(HTTPException) as context: self.run_cleanup()
        self.assertEqual(context.exception.status_code, 502)
        self.sdk['agent'].delete_knowledge_base.assert_not_called()

    def test_unclosed_execution_blocks_deletion(self):
        with tempfile.NamedTemporaryFile() as file:
            with sqlite3.connect(file.name) as db:
                db.execute('CREATE TABLE p02_executions (closed_at REAL)')
                db.execute('INSERT INTO p02_executions VALUES(NULL)')
            with self.assertRaises(HTTPException): module.assert_idle(file.name, 'P02')

    def test_active_preparation_blocks_deletion(self):
        with tempfile.NamedTemporaryFile() as file:
            with sqlite3.connect(file.name) as db:
                db.execute('CREATE TABLE p03_preparations (state TEXT)')
                db.execute("INSERT INTO p03_preparations VALUES('preparing')")
            with self.assertRaises(HTTPException): module.assert_idle(file.name, 'P03')

    def test_closed_execution_is_accepted(self):
        with tempfile.NamedTemporaryFile() as file:
            with sqlite3.connect(file.name) as db:
                db.execute('CREATE TABLE p02_executions (closed_at REAL)')
                db.execute('INSERT INTO p02_executions VALUES(1)')
            module.assert_idle(file.name, 'P02')

if __name__ == '__main__': unittest.main()
