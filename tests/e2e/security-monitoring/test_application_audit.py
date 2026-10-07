"""Run in the real Application image, without AWS or a real upstream model."""
import asyncio
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
import httpx

TEMP = tempfile.TemporaryDirectory()
os.environ.update({"APPLICATION_INTERNAL_TOKEN": "audit-test-internal", "BEDROCK_GATEWAY_TOKEN": "audit-test-bedrock",
                   "AUTH_ADMIN_TOKEN": "audit-test-admin", "AUTH_STATE_DIR": TEMP.name,
                   "SECURITY_MONITOR_URL": "http://test-monitor", "TELEMETRY_INGEST_TOKEN": "audit-test-ingest",
                   "TELEMETRY_HMAC_KEY": "audit-test-hmac", "AUTH_EVENT_SINK": "monitor"})
sys.path.insert(0, "/app")
import server


class ApplicationAuditPaths(unittest.TestCase):
    def events(self):
        with sqlite3.connect(Path(TEMP.name) / "audit-outbox.db") as db:
            rows = db.execute("SELECT body FROM pending ORDER BY rowid").fetchall()
        return [json.loads(row[0]) for row in rows]
    def setUp(self):
        with sqlite3.connect(Path(TEMP.name) / "audit-outbox.db") as db:
            db.execute("DELETE FROM pending")
        self.client = TestClient(server.app, client=("203.0.113.10", 49152))
        login = self.client.post("/.well-known/login", json={"username": "public-reader", "password": "public-reader-demo"})
        self.assertEqual(login.status_code, 200)
        self.headers = {"Authorization": "Bearer " + login.json()["access_token"]}
    def test_authentication_and_schema_failure_are_correlated(self):
        reply = self.client.post("/api/chat", json={"message": "secret-prompt"})
        self.assertEqual(reply.status_code, 401)
        invalid = self.client.post("/api/chat", json={"message": "secret-prompt", "password": "secret-password"}, headers=self.headers)
        self.assertEqual(invalid.status_code, 422)
        events = self.events()
        self.assertTrue(all(len(event["trace_id"]) == 32 for event in events))
        body = json.dumps(events)
        self.assertNotIn("secret-prompt", body)
        self.assertNotIn("secret-password", body)
        self.assertTrue(any(event["event"] == "application_validation" for event in events))
    def test_authorization_failure_stops_before_upstream(self):
        reply = self.client.post("/api/chat", json={"message": "internal", "classification": "internal", "purpose": "incident_response"}, headers=self.headers)
        self.assertEqual(reply.json()["application_decision"], "block")
        event = self.events()[-1]
        self.assertFalse(event["upstream_called"])
        self.assertEqual(event["classification"], "internal")
        self.assertEqual(len(event["subject_hash"]), 64)
    def test_transport_ip_and_authenticated_account_are_retained_without_spoofing(self):
        headers = {**self.headers, "X-Forwarded-For": "198.51.100.99", "Forwarded": "for=198.51.100.99"}
        self.client.post("/api/chat", json={"message": "internal", "classification": "internal", "purpose": "incident_response"}, headers=headers)
        event = self.events()[-1]
        self.assertEqual(event["client_ip"], "203.0.113.10")
        self.assertEqual(event["client_ip_source"], "transport_peer")
        self.assertEqual(event["user_id"], "public-reader")
        self.assertEqual(event["http_path"], "/api/chat")
        self.assertEqual(event["http_method"], "POST")
        self.assertEqual(event["http_status"], 200)
        self.assertEqual(len(event["client_ip_hash"]), 64)
        self.assertNotIn(self.headers["Authorization"], json.dumps(self.events()))
        self.client.post("/.well-known/login", json={"username": "claimed-admin", "password": "secret-password"})
        failed = [item for item in self.events() if item.get("attempted_user_id") == "claimed-admin"][0]
        self.assertNotIn("user_id", failed)
        self.assertEqual(failed["http_status"], 401)
        self.assertEqual(failed["client_ip"], "203.0.113.10")
        self.assertNotIn("secret-password", json.dumps(self.events()))

    def test_identity_reaches_all_normal_and_guardrail_decision_events(self):
        real_client = httpx.AsyncClient
        for blocked in (False, True):
            def upstream(request):
                payload = json.loads(request.content)
                return httpx.Response(200, request=request, json={
                    "request_id": payload["request_id"], "reply": "fixture response",
                    "guardrail": {"decision": "block" if blocked else "allow", "mode": "prevent",
                                  "upstream_called": not blocked, "guard_model_calls": 0,
                                  "stages": [{"stage": "presidio_input", "engine": "presidio", "decision": "block" if blocked else "allow"}]}})
            transport = httpx.MockTransport(upstream)
            with patch.object(server.httpx, "AsyncClient", side_effect=lambda **kw: real_client(transport=transport, **kw)):
                result = self.client.post("/api/chat", json={"message": "fixture"}, headers=self.headers).json()
            events = [e for e in self.events() if e["request_id"] == result["request_id"]]
            self.assertEqual({e["event"] for e in events}, {"control_plane_decision", "control_plane_stage"})
            for event in events:
                self.assertEqual(event["user_id"], "public-reader")
                self.assertEqual(event["client_ip"], "203.0.113.10")
                self.assertEqual(len(event["token_hash"]), 64)
                self.assertEqual(event["http_path"], "/api/chat")

    def test_upstream_http_error_is_recorded_as_unknown_not_no_execution(self):
        real_client = httpx.AsyncClient
        transport = httpx.MockTransport(lambda request: httpx.Response(503, request=request))
        with patch.object(server.httpx, "AsyncClient", side_effect=lambda **kw: real_client(transport=transport, **kw)):
            reply = self.client.post("/api/chat", json={"message": "secret-input"}, headers=self.headers)
        self.assertEqual(reply.json()["application_decision"], "infra")
        self.assertIsNone(reply.json()["upstream_called"])
        self.assertEqual(self.events()[-1]["decision"], "infra")
        self.assertTrue(self.events()[-1]["trace_id"])
    def test_untrusted_trace_context_cannot_merge_incidents_or_disable_recording(self):
        headers = {**self.headers, "traceparent": "00-"+"a"*32+"-"+"b"*16+"-00", "baggage": "password=secret"}
        reply = self.client.post("/api/chat", json={"message": "internal", "classification": "internal", "purpose": "incident_response"}, headers=headers)
        trace_id = reply.json()["trace_id"]
        self.assertEqual(len(trace_id), 32)
        self.assertNotEqual(trace_id, "a"*32)
        self.assertEqual(self.events()[-1]["trace_id"], trace_id)

    def test_invalid_hub_contract_is_an_observed_error(self):
        real_client = httpx.AsyncClient
        for body in ([], {"request_id": "wrong", "reply": "not-trusted", "guardrail": {"decision": "allow"}}):
            transport = httpx.MockTransport(lambda request: httpx.Response(200, request=request, json=body))
            with patch.object(server.httpx, "AsyncClient", side_effect=lambda **kw: real_client(transport=transport, **kw)):
                result = self.client.post("/api/chat", json={"message": "normal"}, headers=self.headers).json()
            self.assertEqual(result["blocking_reason"], "nemo-hub:invalid-contract")
            self.assertIsNone(result["upstream_called"])
            self.assertEqual(self.events()[-1]["decision"], "infra")

    def test_stage_details_and_model_counts_are_not_repeated(self):
        result = {"request_id": "test-request", "trace_id": "a"*32, "authenticated_subject": "reader", "classification": "none",
                  "guardrail": {"mode": "prevent", "decision": "allow", "upstream_called": True, "guard_model_calls": 2,
                                "policy_bundle_version": "1.1.0", "assurance_profile": "high-assurance", "stage_order": ["privacy_input", "bedrock_main"],
                                "stages": [{"stage": "privacy_input", "engine": "presidio", "decision": "allow"},
                                           {"stage": "bedrock_main", "decision": "allow"}]}}
        asyncio.run(server.observe_guardrail(result))
        events = [event for event in self.events() if event["request_id"] == "test-request"]
        self.assertEqual(sum(event["guard_model_calls"] for event in events), 2)
        self.assertEqual(events[1]["stage_name"], "privacy_input")
        self.assertEqual(events[0]["policy_bundle_version"], "1.1.0")


if __name__ == "__main__":
    unittest.main()
