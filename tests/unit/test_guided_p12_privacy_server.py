"""HTTP and durable-state contract using an explicit processor double, not product evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

SOURCE = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs/h12-protected-services/privacy_server.py"
spec = importlib.util.spec_from_file_location("p12_privacy_server", SOURCE)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
TOKENS = {role: f"test-only-{role}" for role in ("control", "service", "verifier")}


def headers(role):
    return {"Authorization": "Bearer " + TOKENS[role]}


class PrivacyServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "ledger.sqlite3"
        self.clock = [1000.0]
        self.calls = []

        def process(stage, text):
            self.calls.append((stage, text))
            return {"text": "transformed", "evidence": {"stage": stage,
                "input_digest": hashlib.sha256(text.encode()).hexdigest(),
                "output_digest": hashlib.sha256(b"transformed").hexdigest()}}

        self.processor = SimpleNamespace(process=process)
        self.client = self.make_client()
        self.suite, self.execution = str(uuid4()), str(uuid4())
        self.body = {"suite_id": self.suite, "execution_id": self.execution,
                     "stage": "input_privacy", "text": "synthetic-private-value"}

    def make_client(self):
        return TestClient(module.create_app(database=self.path, tokens=TOKENS,
                                           processor=self.processor, now=lambda: self.clock[0]))

    def register(self):
        return self.client.post("/v1/suites", headers=headers("control"),
                                json={"suite_id": self.suite, "execution_ids": [self.execution]})

    def ledger(self):
        return self.client.get(f"/v1/suites/{self.suite}/ledger", headers=headers("verifier")).json()

    def process(self, **updates):
        return self.client.post("/v1/process", headers=headers("service"), json={**self.body, **updates})

    def close(self):
        return self.client.post(f"/v1/suites/{self.suite}/close", headers=headers("control"), json={})

    def test_registered_process_closure_and_persistence(self):
        self.assertEqual(self.register().status_code, 200)
        self.assertEqual(self.process().json()["text"], "transformed")
        self.assertEqual(self.process(stage="output_privacy").status_code, 200)
        self.assertEqual(self.close().status_code, 200)
        before = self.ledger()
        self.client = self.make_client()
        self.assertEqual(self.ledger(), before)
        self.assertEqual(before["practice_id"], "P12")
        self.assertEqual([call["state"] for call in before["calls"]], ["completed"] * 2)
        self.assertNotIn(self.body["text"], json.dumps(before))
        self.assertNotIn(self.body["text"].encode(), self.path.read_bytes())
        self.assertNotIn("task_completed", before)

    def test_roles_cannot_substitute_for_each_other(self):
        self.register()
        for role in ("control", "verifier"):
            self.assertEqual(self.client.post("/v1/process", headers=headers(role), json=self.body).status_code, 401)
        for role in ("service", "control"):
            self.assertEqual(self.client.get(f"/v1/suites/{self.suite}/ledger", headers=headers(role)).status_code, 401)
        self.assertEqual(self.client.post("/v1/suites", headers=headers("service"),
                         json={"suite_id": str(uuid4()), "execution_ids": [self.execution]}).status_code, 401)
        self.assertEqual(self.client.post("/v1/process", json=self.body).status_code, 401)
        self.assertFalse(self.calls)

    def test_unknown_and_foreign_execution_rejected(self):
        self.assertEqual(self.process().status_code, 404)
        self.register()
        self.assertEqual(self.process(execution_id=str(uuid4())).status_code, 404)
        self.assertFalse(self.calls)

    def test_replay_and_duplicate_registration_rejected(self):
        self.register()
        self.assertEqual(self.register().status_code, 409)
        self.assertEqual(self.process().status_code, 200)
        self.assertEqual(self.process(text="changed").status_code, 409)
        self.assertEqual(len(self.calls), 1)

    def test_expiry_and_closed_state_prevent_processing(self):
        self.register()
        self.clock[0] += 180
        self.assertEqual(self.process().status_code, 409)
        self.close()
        snapshot = self.ledger()
        self.clock[0] += 1
        self.close()
        self.assertEqual(self.ledger(), snapshot)
        self.assertFalse(self.calls)

    def test_error_is_recorded_and_exception_text_not_returned(self):
        self.register()
        def fail(*_):
            raise RuntimeError("synthetic-secret-in-error")
        self.processor.process = fail
        response = self.process()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("synthetic-secret", response.text)
        self.assertEqual(self.ledger()["calls"][0]["state"], "error")
        self.assertEqual(self.process().status_code, 409)
        self.assertEqual(self.close().status_code, 200)

    def test_close_rejected_while_processing(self):
        self.register()
        original = self.processor.process
        def process(stage, text):
            self.assertEqual(self.close().status_code, 409)
            return original(stage, text)
        self.processor.process = process
        self.assertEqual(self.process().status_code, 200)
        self.assertEqual(self.close().status_code, 200)

    def test_bad_fields_do_not_leak_text_or_reach_processor(self):
        self.register()
        for updates in ({"task_completed": True}, {"stage": "retrieval"}, {"text": " "},
                        {"text": "private" * 3000}, {"suite_id": "not-a-uuid"}):
            response = self.process(**updates)
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.json(), {"detail": "invalid request fields"})
        self.assertFalse(self.calls)
        self.assertEqual(self.ledger()["calls"], [])

    def test_corrupt_product_evidence_rejected(self):
        self.register()
        original = self.processor.process
        def process(stage, text):
            result = original(stage, text)
            result["evidence"]["output_digest"] = "0" * 64
            return result
        self.processor.process = process
        self.assertEqual(self.process().status_code, 503)
        self.assertEqual(self.ledger()["calls"][0]["state"], "error")

    def test_credential_configuration_fails_closed(self):
        for tokens in ({}, {role: "same" for role in TOKENS},
                       *({**TOKENS, "service": value} for value in ("", "비밀", 7, None))):
            with self.assertRaises(ValueError):
                module.create_app(database=self.path, tokens=tokens, processor=self.processor)

    def test_build_identity_is_verifier_only_and_binds_closed_empty_suite(self):
        for role in ("control", "service"):
            self.assertEqual(self.client.get("/v1/build-info", headers=headers(role)).status_code, 401)
        build = self.client.get("/v1/build-info", headers=headers("verifier")).json()
        digest = hashlib.sha256()
        for name in ("privacy_server.py", "privacy.py"):
            digest.update(name.encode())
            digest.update((SOURCE.parent / name).read_bytes())
        self.assertEqual(build["source_digest"], digest.hexdigest())
        self.assertEqual(build["current_source_digest"], digest.hexdigest())
        self.register()
        self.close()
        ledger = self.ledger()
        self.assertEqual(ledger["service_digest"], digest.hexdigest())
        self.assertEqual(ledger["calls"], [])
        self.assertIsNotNone(ledger["closed_at"])

    def test_completed_call_retains_identity_after_restart(self):
        self.register()
        result = self.process().json()
        digest = self.ledger()["service_digest"]
        self.assertEqual(result["evidence"]["service_digest"], digest)
        self.close()
        self.client = self.make_client()
        self.assertEqual(self.ledger()["calls"][0]["evidence"]["service_digest"], digest)

    def test_source_change_before_processing_is_error_without_product_call(self):
        self.register()
        with patch.object(module.Path, "read_bytes", return_value=b"changed source"):
            response = self.process()
        self.assertEqual(response.status_code, 503)
        self.assertFalse(self.calls)
        self.assertEqual(self.ledger()["calls"][0]["state"], "error")
        self.assertIsNone(self.ledger()["calls"][0]["evidence"])

    def test_source_change_during_processing_is_not_completed(self):
        self.register()
        reads = [b"changed"]
        def read(path):
            return original_read(path) if not self.calls else reads[0]
        original_read = module.Path.read_bytes
        with patch.object(module.Path, "read_bytes", read):
            response = self.process()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.ledger()["calls"][0]["state"], "error")
        self.assertIsNone(self.ledger()["calls"][0]["evidence"])

    def test_source_change_prevents_new_suite_registration(self):
        with patch.object(module.Path, "read_bytes", return_value=b"changed source"):
            self.assertEqual(self.register().status_code, 503)
        self.assertFalse(self.calls)
        self.assertEqual(self.client.get(f"/v1/suites/{self.suite}/ledger", headers=headers("verifier")).status_code, 404)

    def test_old_suite_without_identity_is_readable_but_not_executable(self):
        self.register()
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM suite_builds WHERE suite_id=?", (self.suite,))
        self.client = self.make_client()
        self.assertIsNone(self.ledger()["service_digest"])
        self.assertEqual(self.process().status_code, 409)
        self.assertFalse(self.calls)
        self.assertEqual(self.ledger()["calls"], [])

    def test_rebuilt_service_cannot_resume_suite_from_different_source(self):
        self.register()
        before = self.ledger()
        with patch.object(module.Path, "read_bytes", return_value=b"rebuilt"):
            rebuilt = self.make_client()
            self.assertEqual(rebuilt.post("/v1/process", headers=headers("service"), json=self.body).status_code, 409)
            self.assertEqual(rebuilt.get(f"/v1/suites/{self.suite}/ledger", headers=headers("verifier")).json(), before)
        self.assertFalse(self.calls)


if __name__ == "__main__":
    unittest.main()
