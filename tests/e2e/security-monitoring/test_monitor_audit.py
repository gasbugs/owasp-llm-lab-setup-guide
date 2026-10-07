"""Run in the actual Monitor image to verify receipt/dedup/durable OTLP export."""
import json
import os
import sqlite3
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

TEMP = tempfile.TemporaryDirectory()
os.environ.update({"SECURITY_EVENT_DB": TEMP.name + "/events.db", "LLM_MONITOR_TOKEN": "test-reader",
                   "LLM_MONITOR_ADMIN_TOKEN": "test-admin", "TELEMETRY_INGEST_TOKEN": "test-ingest",
                   "TELEMETRY_HMAC_KEY": "test-hmac", "OTEL_EXPORTER_OTLP_ENDPOINT": ""})
sys.path.insert(0, "/app")
import app
import log_delivery
app.OTEL_ENDPOINT = "http://test-alloy"
app.log_delivery.endpoint = "http://test-alloy"
from fastapi.testclient import TestClient


class Reply:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self): return b"{}"


class MonitorAuditPaths(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app.app)
        self.client.__enter__()
        with app.connect() as db:
            db.execute("DELETE FROM events_v2")
            db.execute("DELETE FROM log_outbox")
        self.event = {"event_id": str(uuid.uuid4()), "event": "control_plane_stage", "request_id": "request001",
                      "trace_id": "a"*32, "engine": "nemo", "direction": "input", "decision": "block",
                      "stage_name": "application_self_check_input", "policy_bundle_version": "1.1.0",
                      "guard_model_calls": 1, "message": "secret-prompt", "original_text": "secret-original",
                      "access_token": "secret-token", "subject_hash": "b"*64,
                      "user_id": "public-reader", "client_ip": "203.0.113.10",
                      "client_ip_source": "transport_peer", "http_method": "POST", "http_path": "/api/chat"}
    def tearDown(self):
        self.client.__exit__(None, None, None)
    def send(self):
        return self.client.post("/api/events/guardrail", json=self.event, headers={"X-Telemetry-Token": "test-ingest"})
    def test_acknowledgement_is_durable_and_retry_does_not_inflate_metrics(self):
        initial = app.GUARDRAIL_MODEL_CALLS.labels(engine="nemo")._value.get()
        first, second = self.send(), self.send()
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.json()["delivery_event_id"], self.event["event_id"])
        self.assertTrue(second.json()["duplicate"])
        self.assertEqual(app.GUARDRAIL_MODEL_CALLS.labels(engine="nemo")._value.get()-initial, 1)
        with app.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events_v2").fetchone()[0], 1)
            body = db.execute("SELECT body FROM log_outbox").fetchone()[0]
        for secret in ("secret-prompt", "secret-original", "secret-token"):
            self.assertNotIn(secret, body)
        self.assertIn("application_self_check_input", body)
        self.assertIn("1.1.0", body)
        self.assertIn("203.0.113.10", body)
        self.assertIn("public-reader", body)
        self.assertIn("transport_peer", body)
    def test_committed_log_replays_after_exporter_restart(self):
        self.send()
        with patch.object(log_delivery, "urlopen", side_effect=OSError("down")):
            self.assertFalse(app.log_delivery.flush_once())
        restarted = log_delivery.LogDelivery(app.DATABASE_PATH, "http://test-alloy")
        with patch.object(log_delivery, "urlopen", return_value=Reply()) as send:
            self.assertTrue(restarted.flush_once())
            payload = json.loads(send.call_args.args[0].data)
        record = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
        self.assertEqual(record["traceId"], "a"*32)
        self.assertEqual(json.loads(record["body"]["stringValue"])["id"], self.event["event_id"])
        with app.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM log_outbox").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events_v2").fetchone()[0], 1)


if __name__ == "__main__": unittest.main()
