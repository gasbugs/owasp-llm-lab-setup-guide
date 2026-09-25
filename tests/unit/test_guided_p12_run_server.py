"""ASGI receipt lifecycle with a trusted workflow double, no product/AWS claim."""
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys
from tempfile import TemporaryDirectory
import threading
import unittest
from uuid import uuid4

from fastapi.testclient import TestClient

SOURCE = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs/h12-application-pipeline"
sys.path.insert(0, str(SOURCE))
from run_server import create_app, FILES


class RunServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in FILES:
            shutil.copy2(SOURCE / name, self.root / name)
        self.database = self.root / "runs.sqlite3"
        self.tokens = {"control": "fixture-control", "verifier": "fixture-verifier"}
        self.cases = [{"case_id": "normal", "identity": "reader", "tenant": "team-a", "message": "private fixture text"}]
        self.suite = str(uuid4())
        self.calls = []
        self.hook = lambda: None
        self.status = "returned"
        self.lifecycle = "finished"
        self.client = TestClient(self.make_app())

    def make_app(self):
        return create_app(workflow=self, cases=self.cases, documents=[], tokens=self.tokens,
                          database=self.database, source_root=self.root)

    def run_case(self, source, **kwargs):
        self.calls.append(kwargs)
        self.hook()
        return {"suite_id": kwargs["suite_id"], "execution_id": kwargs["execution_id"],
                "lifecycle_status": self.lifecycle, "closures": {}, "execution": {
                    "execution_status": self.status, "source_digest": hashlib.sha256(Path(source).read_bytes()).hexdigest(), "calls": []}}

    def headers(self, role):
        return {"Authorization": "Bearer " + self.tokens[role]}

    def run_suite(self, **fields):
        return self.client.post("/v1/run", headers=self.headers("control"), json={"suite_id": self.suite, **fields})

    def receipt(self):
        response = self.client.get(f"/v1/receipts/{self.suite}", headers=self.headers("verifier"))
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_receipt_persists_before_side_effect_and_survives_restart(self):
        def inspect_pending():
            value = self.receipt()
            self.assertEqual(value["run_state"], "running")
            self.assertIsNone(value["cases"][0]["lifecycle"])
            self.assertEqual(value["cases"][0]["suite_id"], self.calls[0]["suite_id"])
        self.hook = inspect_pending
        self.assertEqual(self.run_suite().json()["run_state"], "finished")
        before = self.receipt()
        self.client = TestClient(self.make_app())
        self.assertEqual(self.receipt(), before)
        self.assertNotEqual(before["cases"][0]["suite_id"], self.suite)
        self.assertNotIn("private fixture text", json.dumps(before))
        self.assertNotIn("task_completed", before)

    def test_replay_cannot_repeat_effects_or_replace_receipt(self):
        self.run_suite()
        before = self.receipt()
        self.assertEqual(self.run_suite().status_code, 409)
        self.assertEqual(self.receipt(), before)
        self.assertEqual(len(self.calls), 1)

    def test_browser_cannot_choose_cases_inputs_or_verdicts(self):
        for fields in ({"cases": []}, {"message": "new"}, {"task_completed": True}, {"started_at": 0}):
            self.assertEqual(self.run_suite(**fields).status_code, 422)
        self.assertFalse(self.calls)

    def test_tokens_are_separate_and_ready_does_not_execute(self):
        self.assertEqual(self.client.get("/readyz").status_code, 200)
        self.assertEqual(self.client.post("/v1/run", headers=self.headers("verifier"), json={"suite_id": self.suite}).status_code, 401)
        self.assertEqual(self.client.get("/v1/build-info", headers=self.headers("control")).status_code, 401)
        self.assertEqual(self.client.get(f"/v1/receipts/{self.suite}", headers=self.headers("control")).status_code, 401)
        self.assertFalse(self.calls)

    def test_workflow_exception_preserves_unknown_attempt_and_hides_detail(self):
        def fail():
            raise ValueError("private fixture text secret")
        self.hook = fail
        self.assertEqual(self.run_suite().json()["run_state"], "error")
        receipt = self.receipt()
        self.assertIsNone(receipt["cases"][0]["lifecycle"])
        self.assertIsNone(receipt["cases"][0]["finished_at"])
        self.assertNotIn("secret", json.dumps(receipt))

    def test_unimplemented_remains_unimplemented_not_course_success(self):
        self.status = "not_implemented"
        self.run_suite()
        result = self.receipt()
        self.assertEqual(result["cases"][0]["lifecycle"]["execution"]["execution_status"], "not_implemented")
        self.assertNotIn("security_verdict", result)

    def test_unknown_closure_marks_run_error(self):
        self.lifecycle = "error"
        self.assertEqual(self.run_suite().json()["run_state"], "error")

    def test_wrong_execution_binding_is_not_finished(self):
        original = self.run_case
        def wrong(*args, **kwargs):
            return {**original(*args, **kwargs), "execution_id": str(uuid4())}
        self.run_case = wrong
        self.assertEqual(self.run_suite().json()["run_state"], "error")

    def test_changed_source_rejected_before_and_during_execution(self):
        source = self.root / "pipeline.py"
        original = source.read_text()
        source.write_text(original + "\n")
        self.assertEqual(self.run_suite().status_code, 503)
        self.assertFalse(self.calls)
        source.write_text(original)
        self.hook = lambda: source.write_text(original + "\n")
        self.assertEqual(self.run_suite().json()["run_state"], "error")

    def test_previous_interrupted_run_is_not_replayed_on_restart(self):
        row = {"suite_id": self.suite, "run_state": "running", "cases": []}
        with sqlite3.connect(self.database) as db:
            db.execute("INSERT INTO p12_runs VALUES(?,?)", (self.suite, json.dumps(row)))
        self.client = TestClient(self.make_app())
        self.assertEqual(self.receipt(), row)
        self.assertEqual(self.run_suite().status_code, 409)
        self.assertFalse(self.calls)

    def test_concurrent_run_is_refused(self):
        entered, release = threading.Event(), threading.Event()
        def hold():
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test release missing")
        self.hook = hold
        results = []
        thread = threading.Thread(target=lambda: results.append(self.run_suite().status_code))
        thread.start()
        try:
            self.assertTrue(entered.wait(5))
            response = self.client.post("/v1/run", headers=self.headers("control"), json={"suite_id": str(uuid4())})
            self.assertEqual(response.status_code, 409)
        finally:
            release.set()
            thread.join(5)
        self.assertEqual(results, [200])


if __name__ == "__main__":
    unittest.main()
