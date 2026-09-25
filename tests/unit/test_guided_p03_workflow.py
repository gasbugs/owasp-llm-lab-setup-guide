"""Real worker and TCP lifecycle against the P03 API with a synthetic backend."""
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
import uvicorn
import test_guided_p03_api as gateway
import test_guided_p03_execution as worker


spec = importlib.util.spec_from_file_location("p03_workflow_test", worker.LAB / "workflow.py")
workflow = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"execution": worker.module}):
    spec.loader.exec_module(workflow)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.source = Path(temp.name) / "learner.py"
        self.source.write_text(worker.IMPLEMENTATION)
        self.ledger = gateway.ledger_module.SearchLedger(Path(temp.name) / "ledger.sqlite3")
        self.job = "h03-" + uuid4().hex
        self.backend = Mock()
        self.backend.job_status.return_value = {"ingestion_job_id": self.job, "status": "COMPLETE"}
        self.backend.retrieve.return_value = {"source_uris": ["s3://fixture/current.md"]}
        provider = gateway.provider_module.SearchProvider(self.ledger, self.backend)
        app = FastAPI()
        app.mount("/v1/p03", gateway.api.create_app(
            self.ledger, lambda: provider, control_token="workflow-control",
            verifier_token="workflow-verifier", job_resolver=lambda *_: self.job))
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
                self.fail("P03 fixture HTTP server did not start")
            time.sleep(.01)
        self.flow = workflow.Workflow(self.origin, "workflow-control")

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())

    def run_case(self):
        suite, execution = str(uuid4()), str(uuid4())
        result = self.flow.run_case(self.source, suite_id=suite, execution_id=execution,
                                    runner_digest="b" * 64)
        return result, self.ledger.read(execution)

    def test_actual_function_http_and_closed_gateway_record_agree(self):
        result, record = self.run_case()
        self.assertEqual(result["lifecycle_status"], "finished")
        self.assertEqual(result["execution"]["execution_status"], "returned")
        self.assertTrue(record["closed"])
        self.assertEqual([c["operation"] for c in record["calls"]], ["job_status", "retrieve"])
        self.assertEqual(result["execution"]["result"]["result"], record["calls"][1]["response"])
        self.assertEqual(record["source_digest"], result["source_digest"])
        self.assertNotIn("task_completed", result)

    def test_waiting_is_one_observed_call_not_missing_evidence(self):
        self.backend.job_status.return_value["status"] = "IN_PROGRESS"
        result, record = self.run_case()
        self.assertEqual(result["execution"]["result"], {"status": "waiting", "result": None})
        self.assertTrue(record["closed"])
        self.assertEqual([c["operation"] for c in record["calls"]], ["job_status"])
        self.backend.retrieve.assert_not_called()

    def test_unimplemented_function_closes_zero_calls_without_completion(self):
        self.source.write_text((worker.LAB / "learner.py").read_text())
        result, record = self.run_case()
        self.assertEqual(result["execution"]["execution_status"], "not_implemented")
        self.assertTrue(record["closed"])
        self.assertEqual(record["calls"], [])
        self.assertNotIn("task_completed", result)

    def test_provider_failure_closes_error_record_not_waiting(self):
        self.backend.job_status.side_effect = RuntimeError("synthetic failure")
        result, record = self.run_case()
        self.assertEqual(result["execution"]["execution_status"], "service_error")
        self.assertTrue(record["closed"])
        self.assertEqual(record["calls"][0]["state"], "error")
        self.backend.retrieve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
