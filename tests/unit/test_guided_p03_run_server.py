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

import test_guided_p03_workflow as flow
import test_guided_p03_results as results

LAB = flow.worker.LAB


def load(name):
    spec = importlib.util.spec_from_file_location("p03_" + name + "_test", LAB / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cases = load("cases")
flow.gateway.load("p03_backend")
suites = flow.gateway.load("p03_suites")
with patch.dict(sys.modules, {"cases": cases}):
    runner = load("run_server")


class RunnerTests(unittest.TestCase):
    control = {"Authorization": "Bearer runner-control"}
    verifier = {"Authorization": "Bearer runner-verifier"}

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
            tokens={"control": "runner-control", "verifier": "runner-verifier"},
            database=self.database, source_root=self.root))
        self.addCleanup(client.close)
        return client

    def run_suite(self, client=None, suite=None, **extra):
        return (client or self.client).post("/v1/run", headers=self.control,
                                           json={"suite_id": suite or str(uuid4()), **extra})

    def test_health_has_no_provider_or_source_execution(self):
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
        self.assertEqual(len({row["execution_id"] for row in root["cases"]}), 19)
        self.assertEqual(self.workflow.run_case.call_count, 19)
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
        for extra in ({"cases": []}, {"current_job_id": "previous"}, {"task_completed": True}):
            self.assertEqual(self.run_suite(**extra).status_code, 422)
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

    def live_workflow(self):
        self.ledger = flow.gateway.ledger_module.SearchLedger(self.root / "gateway.sqlite3")
        self.synthetic_uri = suites.CONTRACT_URI
        self.store = suites.SuiteStore(self.root / "suites.sqlite3", cases.cases(), lambda: {
            "provider_mode": "contract", "binding": None, "source_uris": [self.synthetic_uri]})
        self.native_factory = Mock(side_effect=AssertionError("contract suite must not call AWS"))
        backend = suites.RegisteredBackend(self.store, self.native_factory)
        self.status = backend.job_status
        provider = flow.gateway.provider_module.SearchProvider(self.ledger, backend)
        app = FastAPI()
        app.mount("/v1/p03", flow.gateway.api.create_app(self.ledger, lambda: provider,
            control_token="workflow-control", verifier_token="workflow-verifier",
            job_resolver=self.store.resolve, suite_preparer=self.store.prepare, suite_reader=self.store.read,
            suite_resources=self.store.inspect_resources))
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self.addCleanup(sock.close)
        self.origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
        server = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="off"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        def stop():
            server.should_exit = True
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.addCleanup(stop)
        deadline = time.monotonic() + 5
        while not server.started:
            if not thread.is_alive() or time.monotonic() >= deadline:
                self.fail("Gateway fixture failed to start")
            time.sleep(.01)
        return flow.workflow.Workflow(self.origin, "workflow-control")

    def test_all_19_cases_execute_actual_child_then_read_only_tcp_verification(self):
        (self.root / "learner.py").write_text(flow.worker.IMPLEMENTATION)
        live = self.client_for(self.live_workflow())
        root = self.run_suite(live).json()
        self.assertEqual(root["run_state"], "finished")
        collector = results.collector.CaseVerification(self.origin, "workflow-verifier")
        for case, row in zip(cases.cases(), root["cases"]):
            job = self.store.resolve(root["suite_id"], row["execution_id"])
            expected = {**case, "suite_id": root["suite_id"], "execution_id": row["execution_id"],
                        "current_job_id": job, "source_uris": [self.synthetic_uri]}
            if case.get("failed_operation") != "job_status":
                expected["status_response"] = self.status(job)
            check = collector.collect(expected, row["execution"],
                source_digest=root["build"]["source_digest"], runner_digest=root["build"]["runner_digest"],
                provider_mode="contract")
            self.assertTrue(check["case_result"]["case_verified"], case["case_id"])
        self.assertEqual(live.get("/v1/receipts/" + root["suite_id"], headers=self.verifier).json(), root)
        self.native_factory.assert_not_called()
        with httpx.Client(trust_env=False) as client:
            url = self.origin + "/v1/p03/suites/" + root["suite_id"]
            self.assertEqual(client.get(url).status_code, 401)
            self.assertEqual(client.get(url, headers={"Authorization": "Bearer workflow-control"}).status_code, 401)
            response = client.get(url, headers={"Authorization": "Bearer workflow-verifier"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), self.store.read(root["suite_id"]))

    def test_actual_starter_records_all_attempts_but_has_no_verified_case(self):
        live = self.client_for(self.live_workflow())
        root = self.run_suite(live).json()
        self.assertEqual(root["run_state"], "finished")
        for row in root["cases"]:
            self.assertEqual(row["execution"]["execution"]["execution_status"], "not_implemented")
            record = self.ledger.read(row["execution_id"])
            self.assertTrue(record["closed"])
            self.assertEqual(record["calls"], [])
            with self.assertRaises(results.module.EvidenceError):
                results.module.verify_case({"suite_id": root["suite_id"], "execution_id": row["execution_id"],
                    "current_job_id": record["current_job_id"]}, row["execution"], record,
                    source_digest=root["build"]["source_digest"], runner_digest=root["build"]["runner_digest"],
                    now=time.time(), provider_mode="contract")


if __name__ == "__main__":
    unittest.main()
