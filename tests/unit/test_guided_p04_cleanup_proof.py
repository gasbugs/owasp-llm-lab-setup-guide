"""Local cleanup prerequisites only: no network and no AWS deletion."""
from copy import deepcopy
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

import test_guided_p04_resource_contract as resources

ROOT = Path(__file__).resolve().parents[2]
with patch.object(sys, 'path', [str(ROOT / 'tests/e2e'), str(resources.GATEWAY), *sys.path]):
    from p04_cleanup_proof import validate_local_ownership
    from p04_preparation import PreparationStore
    from p04_ledger import GuardrailLedger


class CleanupProofTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'journal.sqlite3'
        specification, detail, tags, _ = resources.fixture()
        snapshot = resources.validate_owned(specification, detail, tags, expected_id='p04test')
        self.store = PreparationStore(self.path, now=lambda: 1010)
        self.ledger = GuardrailLedger(self.path, now=lambda: 1020)
        operation = str(uuid4())
        self.store.begin(operation, '000000000000')
        self.store.now = lambda: 1015
        self.prepared = self.store.publish(operation, snapshot,
            {'created': True, 'aws_request_ids': ['create', 'get', 'tags']})
        self.preflight = {'scope': 'read-only P04 absence preflight; no creation or cleanup authorization',
            'preflight_id': str(uuid4()), 'account_id': '000000000000', 'region': 'us-east-1',
            'template_digest': specification['template_digest'], 'name': specification['name'],
            'started_at': 1000, 'finished_at': 1001, 'resources_absent': True,
            'aws_request_ids': ['identity', 'list']}

    def check(self, **kwargs):
        return validate_local_ownership(kwargs.get('preflight', self.preflight),
            kwargs.get('prepared', self.prepared), kwargs.get('path', self.path),
            now=lambda: kwargs.get('now', 1030))

    def test_matching_recent_created_state_is_read_only_and_not_delete_authority(self):
        before = self.path.read_bytes()
        result = self.check()
        self.assertEqual(result['resources'], self.prepared['resources'])
        self.assertIn('live AWS audit still required', result['scope'])
        self.assertEqual(before, self.path.read_bytes())

    def test_existing_or_uncertain_resources_are_rejected(self):
        for field, value in [('created', False), ('created', 1), ('aws_request_ids', ['same'] * 3)]:
            changed = deepcopy(self.prepared)
            changed['evidence'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.check(prepared=changed)
        with self.assertRaises(ValueError):
            self.check(preflight={**self.preflight, 'resources_absent': False})

    def test_wrong_account_region_namespace_digest_and_uuid_are_rejected(self):
        for field, value in [('account_id', '111111111111'), ('region', 'us-west-2'),
                             ('name', 'other'), ('template_digest', 'a' * 64), ('preflight_id', 'bad')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(preflight={**self.preflight, field: value})

    def test_invalid_stale_and_reversed_timestamps_are_rejected(self):
        for value in (True, float('nan'), float('inf'), 0, 1014, 8201):
            with self.subTest(now=value), self.assertRaises(ValueError):
                self.check(now=value)
        for changed in ({'finished_at': 1011}, {'started_at': 800},
                        {'started_at': 600, 'finished_at': 601}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.check(preflight={**self.preflight, **changed})

    def test_reused_native_ids_are_rejected(self):
        with self.assertRaises(ValueError):
            self.check(preflight={**self.preflight, 'aws_request_ids': ['create', 'list']})

    def test_latest_preparation_must_match_original_receipt(self):
        self.store.now = lambda: 1020
        self.store.begin(str(uuid4()), '000000000000')
        with self.assertRaises(ValueError):
            self.check()

    def test_changed_journal_is_rejected(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE p04_preparations SET state='error'")
        with self.assertRaises(ValueError):
            self.check()

    def test_missing_database_or_schema_is_not_initialized(self):
        missing = Path(self.tmp.name) / 'missing.sqlite3'
        with self.assertRaises(ValueError):
            self.check(path=missing)
        self.assertFalse(missing.exists())
        empty = Path(self.tmp.name) / 'empty.sqlite3'
        with sqlite3.connect(empty):
            pass
        before = empty.read_bytes()
        with self.assertRaises(ValueError):
            self.check(path=empty)
        self.assertEqual(before, empty.read_bytes())

    def test_unclosed_execution_blocks_cleanup(self):
        self.ledger.register(str(uuid4()), str(uuid4()), 'a' * 64, 'b' * 64, 'c' * 64,
            'aws', {'operation': 'apply_guardrail', 'text': 'test'}, self.prepared['resources']['guardrail'])
        with self.assertRaises(ValueError):
            self.check()

    def test_pending_call_blocks_cleanup_even_with_no_open_execution(self):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO p04_calls (execution_id,operation,request_json,request_digest,state,started_at) "
                       "VALUES(?,?,?,?,?,?)", (str(uuid4()), 'apply_guardrail', '{}', 'a' * 64, 'pending', 1020))
        with self.assertRaises(ValueError):
            self.check()


if __name__ == '__main__':
    unittest.main()
