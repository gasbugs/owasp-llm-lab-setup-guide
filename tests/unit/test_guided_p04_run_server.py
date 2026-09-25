"""Durable suite runner and real TCP/child execution with contract-only data."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import socket
import sys
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
import uvicorn
import httpx

import test_guided_p04_workflow as flow

LAB = flow.worker.LAB


def load(name):
    spec = importlib.util.spec_from_file_location("p04_" + name + "_test", LAB / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cases = load("cases")
with patch.dict(sys.modules, {"cases": cases}):
    runner = load("run_server")


class RunnerTests(unittest.TestCase):
    control = {"Authorization": "Bearer runner-control-00000000000000000000"}
    verifier = {"Authorization": "Bearer runner-verifier-0000000000000000000"}

    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name in (*runner.RUNNER_FILES, "learner.py"):
            (self.root / name).write_bytes((LAB / name).read_bytes())
        self.database = self.root / "runs.sqlite3"
        self.workflow = Mock()
        self.workflow.run_case.return_value = {"execution_status": "not_implemented"}
        self.client = self.client_for(self.workflow)

    def client_for(self, workflow):
        client = TestClient(runner.create_app(workflow=workflow,
            tokens={"control": "runner-control-00000000000000000000", "verifier": "runner-verifier-0000000000000000000"},
            database=self.database, source_root=self.root))
        self.addCleanup(client.close)
        return client

    def run_suite(self, client=None, suite=None, **extra):
        return (client or self.client).post("/v1/run", headers=self.control,
                                           json={"suite_id": suite or str(uuid4()), **extra})

    def test_health_has_no_provider_or_source_execution(self):
        (self.root / "learner.py").write_text("invalid learner syntax !")
        self.assertEqual(self.client.get("/readyz").json()["provider_check"], "not-run")
        self.workflow.prepare_suite.assert_not_called()
        self.workflow.run_case.assert_not_called()

    def test_all_server_cases_and_unique_ids_are_persisted_before_execution(self):
        def inspect_prepared(*, suite_id, executions, timeout):
            root = self.client.get("/v1/receipts/" + suite_id, headers=self.verifier).json()
            self.assertEqual(root["run_state"], "running")
            self.assertTrue(all(row["execution"] is None for row in root["cases"]))
            self.assertEqual(executions, [{key: row[key] for key in ("case_id", "execution_id")} for row in root["cases"]])
            self.assertEqual(timeout, 30)
        self.workflow.prepare_suite.side_effect = inspect_prepared
        response = self.run_suite()
        self.assertEqual(response.status_code, 200)
        root = response.json()
        self.assertEqual([row["case_id"] for row in root["cases"]], [case["case_id"] for case in cases.cases()])
        self.assertEqual(len({row["execution_id"] for row in root["cases"]}), 27)
        self.assertEqual(self.workflow.run_case.call_count, 27)
        self.assertEqual(root["build"], root["final_build"])
        self.assertNotIn("task_completed", root)
        self.assertEqual(root["run_state"], "finished")

    def test_repeat_suite_survives_restart_and_never_reruns(self):
        root = self.run_suite().json()
        restarted_workflow = Mock()
        restarted = self.client_for(restarted_workflow)
        self.assertEqual(self.run_suite(restarted, root["suite_id"]).status_code, 409)
        self.assertEqual(restarted.get("/v1/receipts/" + root["suite_id"], headers=self.verifier).json(), root)
        restarted_workflow.prepare_suite.assert_not_called()
        restarted_workflow.run_case.assert_not_called()

    def test_preparation_failure_is_durable_not_finished_or_retried(self):
        self.workflow.prepare_suite.side_effect = RuntimeError("private provider information")
        response = self.run_suite()
        root = response.json()
        self.assertEqual(root["run_state"], "error")
        self.assertTrue(all(row["execution"] is None for row in root["cases"]))
        self.assertNotIn("private", response.text)
        self.workflow.run_case.assert_not_called()
        self.assertEqual(self.run_suite(suite=root["suite_id"]).status_code, 409)

    def test_source_change_during_suite_stops_later_cases(self):
        def alter(*_args, **_kwargs):
            (self.root / "learner.py").write_text("# changed\n")
            return {"execution_status": "runtime_error"}
        self.workflow.run_case.side_effect = alter
        root = self.run_suite().json()
        self.assertEqual(root["run_state"], "error")
        self.assertEqual(self.workflow.run_case.call_count, 1)
        self.assertNotEqual(root["build"], root["final_build"])

    def test_browser_cannot_supply_cases_jobs_or_verdicts(self):
        for name in ("cases", "guardrail", "body", "task_completed", "security_verdict"):
            response = self.run_suite(**{name: "private-input-marker"})
            self.assertEqual(response.status_code, 422)
            self.assertNotIn("private-input-marker", response.text)
        self.assertEqual(self.client.post("/v1/run", headers=self.verifier, json={"suite_id": str(uuid4())}).status_code, 401)
        self.assertEqual(self.client.get("/v1/build-info", headers=self.control).status_code, 401)
        self.workflow.prepare_suite.assert_not_called()

    def test_overlapping_request_is_rejected_without_second_preparation(self):
        arrived, release = threading.Event(), threading.Event()
        def wait(**_kwargs):
            arrived.set()
            if not release.wait(5):
                raise TimeoutError()
        self.workflow.prepare_suite.side_effect = wait
        worker = threading.Thread(target=self.run_suite)
        worker.start()
        try:
            self.assertTrue(arrived.wait(5))
            self.assertEqual(self.run_suite().status_code, 409)
        finally:
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(self.workflow.prepare_suite.call_count, 1)

    def test_interrupted_record_survives_restart_without_automatic_resume(self):
        self.workflow.prepare_suite.side_effect = KeyboardInterrupt()
        suite = str(uuid4())
        # Simulate process termination after the durable mapping, before any worker call.
        endpoint = next(route.endpoint for route in self.client.app.routes if route.path == "/v1/run")
        with self.assertRaises(KeyboardInterrupt):
            endpoint(runner.Run(suite_id=suite), authorization=self.control["Authorization"])
        restarted = self.client_for(Mock())
        root = restarted.get("/v1/receipts/" + suite, headers=self.verifier).json()
        self.assertEqual(root["run_state"], "running")
        self.assertIsNone(root["finished_at"])
        self.assertTrue(all(row["execution"] is None for row in root["cases"]))
        self.assertEqual(self.run_suite(restarted, suite).status_code, 409)

    def test_missing_source_is_local_build_error_not_provider_activity(self):
        (self.root / "learner.py").unlink()
        self.assertEqual(self.client.get("/readyz").status_code, 200)
        self.assertEqual(self.run_suite().status_code, 503)
        self.workflow.prepare_suite.assert_not_called()


class RunnerTCPTests(unittest.TestCase):
    def setUp(self):
        self.fixture = flow.WorkflowTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.source.parent
        for name in runner.RUNNER_FILES:
            (self.root / name).write_bytes((LAB / name).read_bytes())
        self.tokens = {"control": flow.gateway.CONTROL, "verifier": flow.gateway.VERIFIER}
        self.client = TestClient(runner.create_app(workflow=self.fixture.flow, tokens=self.tokens,
            database=self.root / "runs.sqlite3", source_root=self.root))
        self.addCleanup(self.client.close)

    def execute_suite(self):
        response = self.client.post("/v1/run", headers=flow.gateway.headers(self.tokens["control"]),
                                    json={"suite_id": str(uuid4())})
        self.assertEqual(response.status_code, 200)
        root = response.json()
        self.assertEqual(root["run_state"], "finished")
        self.assertEqual(root["build"], root["final_build"])
        self.assertEqual(len(root["cases"]), 27)
        with httpx.Client(trust_env=False) as client:
            url = self.fixture.origin + "/v1/p04/suites/" + root["suite_id"]
            registered = client.get(url, headers=flow.gateway.headers(self.tokens["verifier"]))
            self.assertEqual(registered.status_code, 200)
            self.assertEqual(registered.json()["contract_digest"], root["build"]["contract_digest"])
            self.assertEqual(registered.json()["cases"], [
                {key: row[key] for key in ("case_id", "execution_id")} for row in root["cases"]])
        for _ in range(2):
            self.assertEqual(self.client.get("/v1/receipts/" + root["suite_id"],
                headers=flow.gateway.headers(self.tokens["verifier"])).json(), root)
        self.assertNotIn("task_completed", root)
        return root

    def test_solution_executes_27_actual_children_and_preserves_downstream_records(self):
        root = self.execute_suite()
        with httpx.Client(trust_env=False) as client:
            for case, row in zip(cases.cases(), root["cases"]):
                execution = row["execution"]["execution"]
                self.assertEqual(execution["execution_status"], case["expected"])
                response = client.get(self.fixture.origin + "/v1/p04/executions/" + row["execution_id"],
                                      headers=flow.gateway.headers(self.tokens["verifier"]))
                self.assertEqual(response.status_code, 200)
                record = response.json()
                self.assertTrue(record["closed"])
                self.assertEqual(record["body"], case["body"])
                self.assertEqual(record["source_digest"], root["build"]["source_digest"])
                self.assertEqual(record["runner_digest"], root["build"]["runner_digest"])
                if case["expected"] == "returned":
                    self.assertEqual(record["calls"][0]["response"], execution["result"])
        self.assertEqual(len(self.fixture.backend_calls), 9)

    def test_starter_records_all_attempts_but_does_not_receive_a_verdict(self):
        self.fixture.source.write_text((LAB / "learner.py").read_text())
        root = self.execute_suite()
        for row in root["cases"]:
            self.assertEqual(row["execution"]["execution"]["execution_status"], "not_implemented")
            record = self.fixture.ledger.read(row["execution_id"])
            self.assertTrue(record["closed"])
            self.assertEqual(record["calls"], [])
        self.assertEqual(self.fixture.backend_calls, [])


if __name__ == "__main__":
    unittest.main()
