from __future__ import annotations

import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("audit_delivery", ROOT / "llm-security-control-plane/application-gateway/audit_delivery.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Reply:
    def __init__(self, value):
        self.value = value
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def read(self, *args):
        return json.dumps(self.value).encode()


class DurableSecurityDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "outbox.db"
        self.queue = module.AuditDelivery(self.path, "http://collector/events", "token", "identity-key", capacity=2)
    def tearDown(self):
        self.temp.cleanup()
    def rows(self):
        with sqlite3.connect(self.path) as db:
            return db.execute("SELECT event_id,body FROM pending").fetchall()
    def test_metadata_allowlist_and_pseudonymous_identity(self):
        event_id = self.queue.enqueue({"subject": "reader@example.com", "request_id": "r001",
                                      "message": "secret prompt", "password": "password-secret",
                                      "access_token": "token-secret", "client_ip": "192.0.2.2"})
        body = self.rows()[0][1]
        self.assertEqual(json.loads(body)["event_id"], event_id)
        self.assertEqual(len(json.loads(body)["subject_hash"]), 64)
        for secret in ("reader@example.com", "secret prompt", "password-secret", "token-secret", "192.0.2.2"):
            self.assertNotIn(secret, body)
    def test_failed_delivery_survives_restart_and_replays_same_id(self):
        event_id = self.queue.enqueue({"request_id": "r001"})
        with patch.object(module, "urlopen", side_effect=OSError("unavailable")):
            self.assertFalse(self.queue.flush_once())
        restarted = module.AuditDelivery(self.path, self.queue.endpoint, "token", "identity-key")
        with patch.object(module, "urlopen", return_value=Reply({"delivery_event_id": event_id})) as send:
            self.assertTrue(restarted.flush_once())
            self.assertEqual(json.loads(send.call_args.args[0].data)["event_id"], event_id)
        self.assertEqual(self.rows(), [])
    def test_wrong_ack_and_full_queue_do_not_silently_drop_committed_events(self):
        self.queue.enqueue({"request_id": "r001"})
        self.queue.enqueue({"request_id": "r002"})
        self.assertIsNone(self.queue.enqueue({"request_id": "r003"}))
        with patch.object(module, "urlopen", return_value=Reply({"delivery_event_id": "wrong"})):
            self.assertFalse(self.queue.flush_once())
        self.assertEqual(len(self.rows()), 2)
        self.assertIn('result="rejected"} 1', self.queue.metrics())
        self.assertIn('result="failures"} 1', self.queue.metrics())
    def test_sqlite_file_and_events_are_bounded(self):
        self.assertIsNone(self.queue.enqueue({"blocking_reason": "x" * 20000}))
        self.assertEqual(self.rows(), [])


if __name__ == "__main__":
    unittest.main()
