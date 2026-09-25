"""Actual NeMo with deterministic model fixtures: HTTP lifecycle, no Gateway/AWS."""
import asyncio
import json
from pathlib import Path
import socket
import sqlite3
import sys
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch
from urllib.request import Request, build_opener, ProxyHandler
from uuid import uuid4

from fastapi.testclient import TestClient
import uvicorn

from check_guided_p12_nemo import FixtureModel, SOURCE

sys.path.insert(0, str(SOURCE.parent))
from nemo_server import create_app


TOKENS = {role: "fixture-only-" + role for role in ("control", "service", "verifier")}


def headers(role):
    return {"Authorization": "Bearer " + TOKENS[role]}


class ServiceTests(unittest.TestCase):
    tcp_result = None

    def setUp(self):
        self.temp = TemporaryDirectory(prefix="p12-nemo-http-")
        self.addCleanup(self.temp.cleanup)
        self.database = Path(self.temp.name) / "nemo.sqlite3"
        self.clock = [1000.0]
        self.answer = "No"
        self.bindings = []
        self.factory = self.model
        self.app = self.make_app()
        self.client = TestClient(self.app)
        self.suite, self.execution = str(uuid4()), str(uuid4())
        self.body = {"suite_id": self.suite, "execution_id": self.execution,
                     "stage": "input_rail", "text": "교육용 검사 문장", "capability": "fixture-" * 8}

    def model(self, suite, execution, stage, capability):
        self.bindings.append((suite, execution, stage))
        return FixtureModel(self.answer)

    def make_app(self, **kwargs):
        return create_app(model_factory=self.factory, database=self.database, tokens=TOKENS,
                          now=lambda: self.clock[0], **kwargs)

    def register(self):
        return self.client.post("/v1/suites", headers=headers("control"),
                                json={"suite_id": self.suite, "execution_ids": [self.execution]})

    def process(self, **updates):
        return self.client.post("/v1/process", headers=headers("service"), json={**self.body, **updates})

    def ledger(self):
        return self.client.get(f"/v1/suites/{self.suite}/ledger", headers=headers("verifier")).json()

    def close(self):
        return self.client.post(f"/v1/suites/{self.suite}/close", headers=headers("control"), json={})

    def test_three_real_rails_closed_ledger_and_restart(self):
        self.assertEqual(self.register().status_code, 200)
        for stage in ("input_rail", "retrieval_rail", "output_rail"):
            response = self.process(stage=stage)
            self.assertEqual(response.status_code, 200)
            self.assertIs(response.json()["allowed"], True)
        self.assertEqual(self.close().status_code, 200)
        before = self.ledger()
        self.client = TestClient(self.make_app())
        self.assertEqual(self.ledger(), before)
        self.assertEqual(len(before["calls"]), 3)
        build = self.client.get("/v1/build-info", headers=headers("verifier")).json()
        self.assertEqual(build["source_digest"], build["current_source_digest"])
        self.assertEqual(before["service_digest"], build["source_digest"])
        for call in before["calls"]:
            self.assertEqual(call["state"], "completed")
            self.assertEqual(call["evidence"]["service_digest"], build["source_digest"])
        self.assertNotIn(self.body["text"].encode(), self.database.read_bytes())
        self.assertNotIn("task_completed", before)

    def test_block_is_completed_product_call_not_course_verdict(self):
        self.answer = "Yes"
        self.register()
        for stage in ("input_rail", "retrieval_rail", "output_rail"):
            response = self.process(stage=stage)
            self.assertEqual(response.status_code, 200)
            self.assertIs(response.json()["allowed"], False)
            self.assertNotIn("security_verdict", response.json())
        self.assertTrue(all(call["state"] == "completed" for call in self.ledger()["calls"]))

    def test_malformed_classifier_is_503_not_normal_block(self):
        self.answer = "Yes\n"
        self.register()
        for stage in ("input_rail", "retrieval_rail", "output_rail"):
            response = self.process(stage=stage)
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json(), {"detail": "rail processing failed"})
        self.assertTrue(all(call["state"] == "error" and call["evidence"] is None
                            for call in self.ledger()["calls"]))

    def test_roles_and_request_fields_cannot_select_models_or_verdicts(self):
        self.register()
        for role in ("control", "verifier"):
            self.assertEqual(self.client.post("/v1/process", headers=headers(role), json=self.body).status_code, 401)
        for role in ("control", "service"):
            self.assertEqual(self.client.get(f"/v1/suites/{self.suite}/ledger", headers=headers(role)).status_code, 401)
            self.assertEqual(self.client.get("/v1/build-info", headers=headers(role)).status_code, 401)
        for fields in ({"model": "other"}, {"allowed": True}, {"task_completed": True},
                       {"stage": "input_privacy"}, {"text": " "}):
            self.assertEqual(self.process(**fields).status_code, 422)
        self.assertFalse(self.bindings)

    def test_unknown_replay_expired_and_closed_requests_do_not_call_models(self):
        self.assertEqual(self.process().status_code, 404)
        self.register()
        self.assertEqual(self.register().status_code, 409)
        self.assertEqual(self.process(execution_id=str(uuid4())).status_code, 404)
        self.assertEqual(self.process().status_code, 200)
        self.assertEqual(self.process().status_code, 409)
        self.clock[0] += 180
        self.assertEqual(self.process(stage="output_rail").status_code, 409)
        self.close()
        self.assertEqual(self.process(stage="retrieval_rail").status_code, 409)
        self.assertEqual(self.bindings, [(self.suite, self.execution, "input_rail")])

    def test_timeout_records_error_without_claiming_zero_provider_calls(self):
        class Slow(FixtureModel):
            async def generate_async(self, *args, **kwargs):
                await asyncio.sleep(1)
                return await super().generate_async(*args, **kwargs)
        self.factory = lambda *_: Slow("No")
        self.client = TestClient(self.make_app(timeout=.02))
        self.register()
        self.assertEqual(self.process().status_code, 503)
        self.assertEqual(self.ledger()["calls"][0]["state"], "error")
        self.assertNotIn("provider_calls", self.ledger()["calls"][0])

    def test_close_refuses_pending_call(self):
        original = self.factory
        def model(*args):
            self.assertEqual(self.close().status_code, 409)
            return original(*args)
        self.factory = model
        self.client = TestClient(self.make_app())
        self.register()
        self.assertEqual(self.process().status_code, 200)
        self.assertEqual(self.close().status_code, 200)

    def test_model_factory_is_mandatory(self):
        with self.assertRaises(TypeError):
            create_app(database=self.database, tokens=TOKENS)
        with self.assertRaises(ValueError):
            create_app(model_factory=None, database=self.database, tokens=TOKENS)

    def test_source_change_is_rejected_before_model_factory(self):
        self.register()
        original = Path.read_bytes
        def modified(path):
            content = original(path)
            return content + b"\n" if path.name == "retrieval.py" else content
        with patch.object(Path, "read_bytes", modified):
            self.assertEqual(self.process().status_code, 503)
        self.assertFalse(self.bindings)
        self.assertEqual(self.ledger()["calls"][0]["state"], "error")

    def test_invalid_credential_configuration_is_rejected(self):
        for tokens in ({}, {role: "same" for role in TOKENS}, {**TOKENS, "service": ""},
                       {**TOKENS, "service": 1}, {**TOKENS, "service": "비ASCII"}):
            with self.subTest(tokens=list(tokens)), self.assertRaises(ValueError):
                create_app(model_factory=self.model, database=self.database, tokens=tokens)

    def test_changed_build_cannot_resume_old_suite(self):
        self.register()
        before = self.ledger()["service_digest"]
        original = Path.read_bytes
        def modified(path):
            content = original(path)
            return content + b"\n" if path.name == "retrieval.py" else content
        with patch.object(Path, "read_bytes", modified):
            self.client = TestClient(self.make_app())
            self.assertEqual(self.process().status_code, 503)
            self.assertEqual(self.ledger()["service_digest"], before)
            self.assertEqual(self.close().status_code, 200)
        self.assertFalse(self.bindings)
        self.assertEqual(self.ledger()["calls"][0]["state"], "error")

    def test_legacy_suite_without_build_is_not_silently_adopted(self):
        self.register()
        with sqlite3.connect(self.database) as db:
            db.execute("DELETE FROM suite_builds WHERE suite_id=?", (self.suite,))
        self.client = TestClient(self.make_app())
        self.assertIsNone(self.ledger()["service_digest"])
        self.assertEqual(self.process().status_code, 503)
        self.assertFalse(self.bindings)

    def test_source_change_during_processing_invalidates_result(self):
        self.register()
        changed = [False]
        original_read = Path.read_bytes
        original_factory = self.factory
        def modified(path):
            content = original_read(path)
            return content + b"\n" if changed[0] and path.name == "retrieval.py" else content
        def factory(*args):
            changed[0] = True
            return original_factory(*args)
        self.factory = factory
        self.client = TestClient(self.make_app())
        with patch.object(Path, "read_bytes", modified):
            self.assertEqual(self.process().status_code, 503)
        self.assertEqual(len(self.bindings), 1)
        self.assertEqual(self.ledger()["calls"][0]["state"], "error")

    def test_changed_live_source_cannot_register_new_suite(self):
        original = Path.read_bytes
        def modified(path):
            content = original(path)
            return content + b"\n" if path.name == "retrieval.py" else content
        with patch.object(Path, "read_bytes", modified):
            self.assertEqual(self.register().status_code, 503)

    def test_actual_tcp_three_stages_and_closed_ledger(self):
        opener = build_opener(ProxyHandler({}))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(128)
            origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
            app = create_app(model_factory=self.model, database=self.database, tokens=TOKENS)
            server = uvicorn.Server(uvicorn.Config(app, log_level="warning", access_log=False))
            thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
            thread.start()
            def request(path, role=None, payload=None):
                request_headers = {"Content-Type": "application/json", **(headers(role) if role else {})}
                req = Request(origin + path, headers=request_headers,
                              data=json.dumps(payload).encode() if payload is not None else None)
                with opener.open(req, timeout=10) as response:
                    self.assertEqual(response.status, 200)
                    return json.load(response)
            try:
                deadline = time.monotonic() + 10
                while not server.started and thread.is_alive() and time.monotonic() < deadline:
                    time.sleep(.05)
                self.assertTrue(server.started)
                request("/readyz")
                request("/v1/suites", "control", {"suite_id": self.suite, "execution_ids": [self.execution]})
                for stage in ("input_rail", "retrieval_rail", "output_rail"):
                    self.assertTrue(request("/v1/process", "service", {**self.body, "stage": stage})["allowed"])
                request(f"/v1/suites/{self.suite}/close", "control", {})
                ledger = request(f"/v1/suites/{self.suite}/ledger", "verifier")
                self.assertEqual(len(ledger["calls"]), 3)
                self.assertIsNotNone(ledger["closed_at"])
                self.assertLess(ledger["created_at"], ledger["closed_at"])
                self.assertEqual([row["stage"] for row in ledger["calls"]],
                                 ["input_rail", "retrieval_rail", "output_rail"])
                for row in ledger["calls"]:
                    self.assertLessEqual(ledger["created_at"], row["started"])
                    self.assertLess(row["started"], row["finished"])
                    self.assertLessEqual(row["finished"], ledger["closed_at"])
                self.__class__.tcp_result = ledger
            finally:
                server.should_exit = True
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    program = unittest.main(verbosity=2, exit=False)
    if not program.result.wasSuccessful():
        sys.exit(1)
    print(json.dumps({"scope": "actual NeMo / ASGI lifecycle and loopback TCP, fixture classifier; no Gateway/AWS/Browser",
                      "tests": program.result.testsRun, "tcp_ledger": ServiceTests.tcp_result}, ensure_ascii=False))
