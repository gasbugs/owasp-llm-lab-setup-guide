"""P04 real child -> TCP -> persistent suite and call ledger; synthetic provider only."""
import hashlib
import importlib.util
import json
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
import httpx
import uvicorn
import test_guided_p04_api as gateway
import test_guided_p04_execution as worker
from test_guided_p04_suites import SuiteStore, case_module

spec = importlib.util.spec_from_file_location("p04_workflow_test", worker.LAB / "workflow.py")
workflow = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"execution": worker.module}):
    spec.loader.exec_module(workflow)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.source = Path(temp.name) / "learner.py"
        self.source.write_text(worker.IMPLEMENTATION)
        path = Path(temp.name) / "ledger.sqlite3"
        self.ledger = gateway.GuardrailLedger(path)
        self.resources = {"provider_mode": "contract", "guardrail": {
            "guardrailIdentifier": "p04contract", "guardrailVersion": "DRAFT"},
            "guardrail_arn": None, "policy_digest": "c" * 64}
        self.store = SuiteStore(path, case_module.cases(), lambda: self.resources)
        self.backend_calls = []

        def invocation_for(suite, execution):
            case = self.store.lookup(suite, execution)["case"]

            def backend(operation, arguments):
                self.backend_calls.append((execution, operation, arguments))
                if case["provider_error"]:
                    raise RuntimeError("synthetic provider failure")
                return {"fixture": "not AWS or a security verdict", "operation": operation,
                        "text": case["body"]["text"]}

            return gateway.Invocation(self.ledger, backend,
                lambda: self.store.resolve(suite, execution)["resource_digest"])

        app = FastAPI()
        app.mount("/v1/p04", gateway.create_app(self.ledger, control_token=gateway.CONTROL,
            verifier_token=gateway.VERIFIER, invocation_for=invocation_for, suite_store=self.store))
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self.addCleanup(sock.close)
        self.origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
        self.server = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="off"))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [sock]}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        deadline = time.monotonic() + 5
        while not self.server.started:
            if not self.thread.is_alive() or time.monotonic() >= deadline:
                self.fail("P04 fixture HTTP server did not start")
            time.sleep(.01)
        self.flow = workflow.Workflow(self.origin, gateway.CONTROL)
        self.suite = str(uuid4())
        self.rows = [{"case_id": case["case_id"], "execution_id": str(uuid4())}
                     for case in case_module.cases()]
        self.flow.prepare_suite(suite_id=self.suite, executions=self.rows)

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())

    def run_case(self, index=0, **kwargs):
        result = self.flow.run_case(self.source, suite_id=self.suite,
            execution_id=self.rows[index]["execution_id"], runner_digest="b" * 64, **kwargs)
        return result, self.ledger.read(self.rows[index]["execution_id"])

    def test_actual_function_all_cases_and_closed_gateway_records_agree(self):
        for index, case in enumerate(case_module.cases()):
            with self.subTest(case=case["case_id"]):
                result, record = self.run_case(index)
                self.assertEqual(result["lifecycle_status"], "finished")
                self.assertEqual(result["execution"]["execution_status"], case["expected"])
                self.assertTrue(record["closed"])
                self.assertEqual(record["source_digest"], result["source_digest"])
                self.assertEqual(len(record["calls"]), 0 if case["expected"] == "rejected" else 1)
                if case["expected"] == "returned":
                    self.assertEqual(result["execution"]["result"], record["calls"][0]["response"])
                if case["provider_error"]:
                    self.assertEqual(record["calls"][0]["state"], "error")
                    self.assertIsNotNone(record["calls"][0]["dispatched_at"])
                self.assertNotIn("capability", json.dumps(result))
                self.assertNotIn("task_completed", result)
        self.assertEqual(len(self.backend_calls), 9)

    def test_starter_closes_observed_zero_calls_without_a_verdict(self):
        self.source.write_text((worker.LAB / "learner.py").read_text())
        result, record = self.run_case()
        self.assertEqual(result["execution"]["execution_status"], "not_implemented")
        self.assertTrue(record["closed"])
        self.assertEqual(record["calls"], [])
        self.assertEqual(self.backend_calls, [])
        self.assertNotIn("security_verdict", result)

    def test_duplicate_execution_does_not_close_or_repeat_another_attempt(self):
        self.ledger.register(self.suite, self.rows[0]["execution_id"], "a" * 64, "b" * 64,
                             **self.store.resolve(self.suite, self.rows[0]["execution_id"]))
        result, record = self.run_case()
        self.assertEqual(result["lifecycle_status"], "error")
        self.assertEqual(result["closure"], {"state": "unknown"})
        self.assertFalse(record["closed"])
        self.assertEqual(self.backend_calls, [])

    def test_resource_change_stops_before_worker_and_provider(self):
        self.resources["policy_digest"] = "d" * 64
        mock = Mock()
        self.flow.worker = mock
        result = self.flow.run_case(self.source, suite_id=self.suite,
            execution_id=self.rows[0]["execution_id"], runner_digest="b" * 64)
        self.assertEqual(result["lifecycle_status"], "error")
        mock.assert_not_called()
        self.assertEqual(self.backend_calls, [])

    def test_source_change_between_registration_and_execution_is_error(self):
        original = self.source.read_text()

        def mutate(*args, **kwargs):
            self.source.write_text(original + "\n# equivalent edit\n")
            return worker.module.execute(*args, **kwargs)

        self.flow.worker = mutate
        result, record = self.run_case()
        self.assertEqual(result["lifecycle_status"], "error")
        self.assertNotEqual(result["source_digest"], result["execution"]["source_digest"])
        self.assertTrue(record["closed"])

    def test_timeout_remains_timeout_and_does_not_claim_zero_worker_calls(self):
        self.source.write_text("async def invoke_guarded(body, guardrail, services):\n    while True: pass\n")
        result, record = self.run_case(timeout=.5)
        self.assertEqual(result["execution"]["execution_status"], "timeout")
        self.assertIsNone(result["execution"]["calls"])
        self.assertTrue(record["closed"])
        self.assertEqual(record["calls"], [])


class LifecycleBoundaryTests(unittest.TestCase):
    def test_bad_grant_or_unconfirmed_closure_cannot_finish_lifecycle(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "learner.py"
            source.write_text(worker.IMPLEMENTATION)
            source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
            suite, execution = str(uuid4()), str(uuid4())
            for fault in ("identity", "closure-time", "closure-identity", "closure-http"):
                fake_worker = Mock(return_value={"source_digest": source_digest,
                    "execution_status": "returned", "calls": [], "result": {}})

                def handle(request):
                    if request.url.path.endswith("/close"):
                        if fault == "closure-http":
                            return httpx.Response(503)
                        return httpx.Response(200, json={
                            "execution_id": str(uuid4()) if fault == "closure-identity" else execution,
                            "closed_at": 999 if fault == "closure-time" else 1001})
                    return httpx.Response(200, json={"suite_id": suite, "execution_id": execution,
                        "practice_id": "P03" if fault == "identity" else "P04", "activity_id": "H04",
                        "contract_version": "p04-guardrail-v1", "started_at": 1000,
                        "capability": "temporary-capability-" * 3,
                        "body": {"operation": "apply_guardrail", "text": "normal"},
                        "guardrail": {"guardrailIdentifier": "p04contract", "guardrailVersion": "DRAFT"}})

                flow = workflow.Workflow("http://fixture", gateway.CONTROL,
                    transport=httpx.MockTransport(handle), worker=fake_worker)
                result = flow.run_case(source, suite_id=suite, execution_id=execution, runner_digest="b" * 64)
                self.assertEqual(result["lifecycle_status"], "error")
                if fault == "identity":
                    fake_worker.assert_not_called()
                else:
                    self.assertEqual(result["closure"], {"state": "unknown"})
                self.assertNotIn("temporary-capability", json.dumps(result))

    def test_suite_mapping_reply_must_match_and_credentials_are_not_redirected(self):
        suite = str(uuid4())
        rows = [{"case_id": "normal", "execution_id": str(uuid4())}]
        for response in (httpx.Response(302, headers={"Location": "http://elsewhere"}),
                         httpx.Response(200, json={"prepared": True}),
                         httpx.Response(200, content=b" " * 65537)):
            calls = []

            def handle(request):
                calls.append(request)
                return response

            flow = workflow.Workflow("http://fixture", gateway.CONTROL,
                                     transport=httpx.MockTransport(handle))
            with self.assertRaises(workflow.LifecycleError):
                flow.prepare_suite(suite_id=suite, executions=rows)
            self.assertEqual(len(calls), 1)

    def test_invalid_mappings_fail_before_network(self):
        transport = Mock(side_effect=AssertionError("network must not run"))
        flow = workflow.Workflow("http://fixture", gateway.CONTROL,
                                 transport=httpx.MockTransport(transport))
        suite = str(uuid4())
        row = {"case_id": "normal", "execution_id": str(uuid4())}
        for rows in ([], [row, row], [None], [{**row, "body": "caller"}]):
            with self.assertRaises(ValueError):
                flow.prepare_suite(suite_id=suite, executions=rows)
        transport.assert_not_called()


if __name__ == "__main__":
    unittest.main()
