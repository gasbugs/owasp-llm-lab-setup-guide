"""Trusted suite server with a workflow double; actual workflow TCP is tested separately."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs/h02-document-ingestion"
with patch.dict(sys.modules):
    for name in ("cases", "run_server"):
        spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
        value = importlib.util.module_from_spec(spec)
        sys.modules[name] = value
        spec.loader.exec_module(value)
    module = sys.modules["run_server"]
    case_module = sys.modules["cases"]


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in (*module.RUNNER_FILES, "learner.py"):
            shutil.copyfile(ROOT / name, self.root / name)
        self.workflow = Mock()
        self.workflow.run_case.return_value = {"lifecycle_status": "finished", "execution": {"execution_status": "not_implemented"}}
        self.tokens = {"control": "control-fixture", "verifier": "verifier-fixture"}
        self.database = self.root / "runs.sqlite3"
        self.client = self.make_client()
        self.suite = str(uuid4())
        self.control = {"Authorization": "Bearer control-fixture"}
        self.verifier = {"Authorization": "Bearer verifier-fixture"}

    def make_client(self):
        client = TestClient(module.create_app(workflow=self.workflow, tokens=self.tokens,
                           database=self.database, source_root=self.root))
        self.addCleanup(client.close)
        return client

    def run_suite(self, **extra):
        return self.client.post("/v1/run", headers=self.control, json={"suite_id": self.suite, **extra})

    def test_all_server_owned_cases_have_fresh_ids_and_persistent_receipt(self):
        result = self.run_suite()
        self.assertEqual(result.status_code, 200)
        root = result.json()
        self.assertEqual(root["run_state"], "finished")
        self.assertEqual(len(root["cases"]), 22)
        self.assertEqual(len({row["execution_id"] for row in root["cases"]}), 22)
        self.assertEqual(root["build"], root["final_build"])
        self.assertNotIn("task_completed", root)
        self.assertEqual(self.workflow.run_case.call_count, 22)
        restarted = self.make_client()
        observed = restarted.get("/v1/receipts/" + self.suite, headers=self.verifier).json()
        self.assertEqual(observed, root)
        for call in self.workflow.run_case.call_args_list:
            self.assertLessEqual(call.kwargs["timeout"], 75)
            self.assertEqual(call.kwargs["suite_id"], self.suite)

    def test_contract_has_four_normal_and_eighteen_invalid_cases(self):
        cases = case_module.cases()
        self.assertEqual(sum(case["valid"] for case in cases), 4)
        self.assertEqual(len(cases), 22)
        self.assertEqual(len(cases[1]["body"]["body"]), 10)
        self.assertEqual(len(cases[2]["body"]["body"]), 4000)
        self.assertEqual(len(cases[2]["body"]["title"]), 120)

    def test_repeated_suite_never_reexecutes(self):
        original = self.run_suite().json()
        self.assertEqual(self.run_suite().status_code, 409)
        self.assertEqual(self.workflow.run_case.call_count, 22)
        self.assertEqual(self.client.get("/v1/receipts/" + self.suite, headers=self.verifier).json(), original)

    def test_source_syntax_does_not_break_health_and_health_does_not_call_workflow(self):
        (self.root / "learner.py").write_text("def broken(:")
        self.assertEqual(self.client.get("/readyz").status_code, 200)
        self.assertEqual(self.client.get("/livez").status_code, 200)
        self.workflow.run_case.assert_not_called()

    def test_unauthorized_calls_and_browser_case_or_verdict_submission(self):
        self.assertEqual(self.client.post("/v1/run", json={"suite_id": self.suite}).status_code, 401)
        self.assertEqual(self.run_suite(cases=[]).status_code, 422)
        self.assertEqual(self.run_suite(task_completed=True).status_code, 422)
        self.assertEqual(self.client.get("/v1/build-info", headers=self.control).status_code, 401)
        self.assertEqual(self.client.get("/v1/receipts/" + self.suite, headers=self.control).status_code, 401)
        self.workflow.run_case.assert_not_called()

    def test_source_change_stops_suite_and_keeps_prior_case(self):
        def change(*args, **kwargs):
            (self.root / "learner.py").write_text("# changed")
            return {"lifecycle_status": "finished"}
        self.workflow.run_case.side_effect = change
        root = self.run_suite().json()
        self.assertEqual(root["run_state"], "error")
        self.assertIsNotNone(root["cases"][0]["execution"])
        self.assertIsNone(root["cases"][1]["execution"])
        self.assertNotEqual(root["build"], root["final_build"])

    def test_unreadable_final_source_keeps_error_receipt(self):
        def remove(*args, **kwargs):
            (self.root / "learner.py").unlink()
            raise RuntimeError("secret detail")
        self.workflow.run_case.side_effect = remove
        root = self.run_suite().json()
        self.assertEqual(root["run_state"], "error")
        self.assertIsNone(root["final_build"])
        self.assertNotIn("secret detail", json.dumps(root))
        self.assertEqual(self.client.get("/v1/receipts/" + self.suite, headers=self.verifier).json(), root)

    def test_concurrent_suite_rejected_without_blocking_readiness(self):
        entered, release = threading.Event(), threading.Event()
        def waiting(*args, **kwargs):
            entered.set()
            release.wait(timeout=5)
            return {"lifecycle_status": "finished"}
        self.workflow.run_case.side_effect = waiting
        thread = threading.Thread(target=self.run_suite)
        thread.start()
        try:
            self.assertTrue(entered.wait(timeout=3))
            response = self.client.post("/v1/run", headers=self.control, json={"suite_id": str(uuid4())})
            self.assertEqual(response.status_code, 409)
            self.assertEqual(self.client.get("/readyz").status_code, 200)
        finally:
            release.set()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
