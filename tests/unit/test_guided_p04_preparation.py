"""Durable preparation invariants; fixtures do not claim real AWS provisioning."""
from copy import deepcopy
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest
from uuid import uuid4

from test_guided_p04_resource_contract import GATEWAY, fixture, validate_owned, LedgerError

sys.path.insert(0, str(GATEWAY))
try:
    from p04_preparation import PreparationStore
finally:
    sys.path.remove(str(GATEWAY))


class PreparationTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / 'gateway.sqlite3'
        self.now = 1000
        self.store = PreparationStore(self.path, now=lambda: self.now)
        specification, detail, tags, _ = fixture()
        self.snapshot = validate_owned(specification, detail, tags, expected_id='p04test')
        self.evidence = {'aws_request_ids': ['list-id', 'get-id', 'tags-id'], 'created': False}
        self.operation = str(uuid4())

    def begin(self):
        return self.store.begin(self.operation, '000000000000')

    def ready(self):
        self.begin()
        self.now += 1
        return self.store.publish(self.operation, self.snapshot, self.evidence)

    def test_ready_is_durable_and_contains_no_course_grade(self):
        result = self.ready()
        self.assertEqual(result['state'], 'ready')
        self.assertEqual(result['practice_id'], 'P04')
        self.assertEqual(result['resources'], self.snapshot)
        self.assertEqual(result['evidence'], self.evidence)
        self.assertNotIn('security_verdict', result)
        self.assertEqual(PreparationStore(self.path).resources(), self.snapshot)

    def test_absent_pending_and_failed_are_not_ready(self):
        with self.assertRaises(LedgerError):
            self.store.resources()
        self.begin()
        with self.assertRaises(LedgerError):
            self.store.resources()
        self.store.fail(self.operation)
        self.assertEqual(self.store.read(self.operation)['state'], 'error')
        with self.assertRaises(LedgerError):
            self.store.resources()

    def test_new_pending_and_failed_operation_invalidate_previous_success(self):
        old = self.ready()
        self.operation = str(uuid4())
        self.begin()
        for store in (self.store, PreparationStore(self.path)):
            with self.assertRaises(LedgerError):
                store.resources()
        self.store.fail(self.operation)
        with self.assertRaises(LedgerError):
            self.store.resources()
        self.assertEqual(self.store.read(old['operation_id'])['state'], 'ready')

    def test_duplicate_and_concurrent_requests_never_overwrite(self):
        self.begin()
        for operation in (self.operation, str(uuid4())):
            with self.assertRaises(LedgerError):
                PreparationStore(self.path).begin(operation, '000000000000')
        self.assertEqual(self.store.read(self.operation)['state'], 'preparing')
        self.store.fail(self.operation)
        with self.assertRaises(LedgerError):
            self.begin()

    def test_account_and_namespace_do_not_mix(self):
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE resource_state (logical_name TEXT PRIMARY KEY,state_json TEXT)')
            db.execute("INSERT INTO resource_state VALUES('h04','legacy-state')")
        self.ready()
        with self.assertRaises(LedgerError):
            self.store.begin(str(uuid4()), '111111111111')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT * FROM resource_state').fetchall(), [('h04', 'legacy-state')])

    def test_wrong_policy_account_contract_mode_or_missing_evidence_cannot_publish(self):
        self.begin()
        snapshots = [dict(self.snapshot, policy_digest='f' * 64),
                     dict(self.snapshot, guardrail_arn=self.snapshot['guardrail_arn'].replace('000000000000', '111111111111')),
                     {'provider_mode': 'contract', 'guardrail': {'guardrailIdentifier': 'p04contract', 'guardrailVersion': 'DRAFT'},
                      'guardrail_arn': None, 'policy_digest': self.snapshot['policy_digest']}]
        for value in snapshots:
            with self.assertRaises(LedgerError):
                self.store.publish(self.operation, value, self.evidence)
        for value in ({}, None, {'aws_request_ids': ['duplicate'] * 3, 'created': False},
                      {'aws_request_ids': ['a', 'b', 'c'], 'created': 1},
                      {'aws_request_ids': ['a', 'b'], 'created': True}):
            with self.assertRaises(LedgerError):
                self.store.publish(self.operation, self.snapshot, value)
        self.assertEqual(self.store.read(self.operation)['state'], 'preparing')

    def test_timeout_and_clock_reversal_cannot_publish(self):
        self.begin()
        for value in (999, 1301, float('nan'), True):
            self.now = value
            with self.assertRaises(LedgerError):
                self.store.publish(self.operation, self.snapshot, self.evidence)

    def test_terminal_state_cannot_be_rewritten(self):
        self.ready()
        with self.assertRaises(LedgerError):
            self.store.fail(self.operation)
        with self.assertRaises(LedgerError):
            self.store.publish(self.operation, self.snapshot, self.evidence)
        self.assertEqual(self.store.resources(), self.snapshot)

    def test_corrupted_template_binding_is_not_exposed(self):
        self.ready()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE p04_preparations SET template_digest='old'")
        with self.assertRaises(LedgerError):
            self.store.resources()


if __name__ == '__main__':
    unittest.main()
