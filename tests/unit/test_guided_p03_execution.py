"""Execute P03 code in a real child against a local HTTP fixture, never AWS."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

LAB = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs/h03-ingestion-search"
spec = importlib.util.spec_from_file_location("p03_execution_test", LAB / "execution.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

IMPLEMENTATION = '''
async def search_current(current_job_id, services):
    observed = await services.job_status()
    if observed.get("ingestion_job_id") != current_job_id:
        raise ValueError("different job")
    status = observed.get("status")
    if status in ("QUEUED", "STARTING", "IN_PROGRESS"):
        return {"status": "waiting", "result": None}
    if status != "COMPLETE":
        raise ValueError("unusable status")
    return {"status": "ready", "result": await services.retrieve()}
'''


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "learner.py"
        self.requests = []
        self.current = "h03-" + uuid4().hex
        self.observed = {"ingestion_job_id": self.current, "status": "COMPLETE"}
        self.retrieval = {"source_uris": ["s3://fixture/current.md"], "provider_request_id": "fixture-id"}
        self.fault = None
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.requests.append((self.path, body))
                response = {key: body[key] for key in ("suite_id", "execution_id", "operation")}
                response["response"] = owner.observed if body["operation"] == "job_status" else owner.retrieval
                if owner.fault == "binding":
                    response["execution_id"] = str(uuid4())
                raw = json.dumps(response).encode()
                if owner.fault == "size":
                    raw = b" " * 17000
                status = 502 if owner.fault == "error" else 302 if owner.fault == "redirect" else 200
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                if status == 302:
                    self.send_header("Location", owner.configuration["origin"] + "/unexpected")
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.configuration = {"suite_id": str(uuid4()), "execution_id": str(uuid4()),
                              "origin": f"http://127.0.0.1:{self.server.server_port}",
                              "capability": "synthetic-p03-only-" * 3}

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def run_source(self, source=IMPLEMENTATION, **kwargs):
        self.source.write_text(source)
        return module.execute(self.source, self.current, self.configuration, **kwargs)

    def test_complete_job_calls_real_adapter_then_returns_actual_response(self):
        result = self.run_source()
        self.assertEqual(result["execution_status"], "returned")
        self.assertEqual(result["result"], {"status": "ready", "result": self.retrieval})
        self.assertEqual([body["operation"] for _, body in self.requests], ["job_status", "retrieve"])
        self.assertTrue(all(path == "/v1/p03/invoke" and body["payload"] == {} for path, body in self.requests))
        self.assertNotIn(self.configuration["capability"], json.dumps(result))
        self.assertNotIn("task_completed", result)

    def test_three_progress_states_do_not_retrieve(self):
        for status in ("QUEUED", "STARTING", "IN_PROGRESS"):
            with self.subTest(status=status):
                self.requests.clear()
                self.observed["status"] = status
                result = self.run_source()
                self.assertEqual(result["result"], {"status": "waiting", "result": None})
                self.assertEqual(len(self.requests), 1)

    def test_other_job_or_unusable_state_is_rejected_before_search(self):
        observations = [
            {"ingestion_job_id": "other", "status": "COMPLETE"}, {},
            *({"ingestion_job_id": self.current, "status": status}
              for status in ("FAILED", "STOPPING", "STOPPED", "UNKNOWN", None, True)),
        ]
        for observed in observations:
            with self.subTest(observed=observed):
                self.requests.clear()
                self.observed = observed
                self.assertEqual(self.run_source()["execution_status"], "rejected")
                self.assertEqual(len(self.requests), 1)

    def test_gateway_failure_is_not_waiting_or_completion(self):
        for fault in ("error", "redirect", "binding", "size"):
            with self.subTest(fault=fault):
                self.requests.clear()
                self.fault = fault
                result = self.run_source()
                self.assertEqual(result["execution_status"], "service_error")
                self.assertEqual(result["calls"][0]["state"], "error")
                self.assertEqual(len(self.requests), 1)

    def test_equivalent_implementation_has_different_digest_same_result(self):
        alternate = IMPLEMENTATION.replace(
            'return {"status": "ready", "result": await services.retrieve()}',
            'found = await services.retrieve()\n    return dict(result=found, status="ready")',
        ) + "\n# harmless comment\n"
        first, second = self.run_source(), self.run_source(alternate)
        self.assertEqual(first["result"], second["result"])
        self.assertNotEqual(first["source_digest"], second["source_digest"])

    def test_starter_syntax_and_wrong_return_are_not_success(self):
        for source, status in (
            ((LAB / "learner.py").read_text(), "not_implemented"),
            ("def broken(:", "runtime_error"),
            ('async def search_current(*args): return {"status":"ready","result":None}', "invalid_return"),
        ):
            self.assertEqual(self.run_source(source)["execution_status"], status)
        self.assertEqual(self.requests, [])

    def test_constant_result_is_not_a_self_awarded_pass(self):
        result = self.run_source('async def search_current(*args): return {"status":"waiting","result":None}')
        self.assertEqual(result["execution_status"], "returned")
        self.assertEqual(result["calls"], [])
        self.assertNotIn("task_completed", result)

    def test_worker_does_not_inherit_parent_secret(self):
        source = '''
import os
async def search_current(*args):
    if "P03_PARENT_SECRET" in os.environ:
        raise RuntimeError()
    return {"status":"waiting","result":None}
'''
        with patch.dict(os.environ, {"P03_PARENT_SECRET": "not-for-worker"}):
            self.assertEqual(self.run_source(source)["execution_status"], "returned")

    def test_timeout_and_source_limit_preserve_unknown_calls(self):
        result = self.run_source("async def search_current(*args):\n    while True: pass", timeout=.2)
        self.assertEqual(result["execution_status"], "timeout")
        self.assertIsNone(result["calls"])
        self.assertEqual(self.run_source("#" * 65537)["execution_status"], "source_limit")

    def test_invalid_job_or_extra_credential_stops_before_worker(self):
        for current in ("", "a" * 129, "job/id", 1, "작업"):
            self.current = current
            self.assertEqual(self.run_source()["execution_status"], "invalid_input")
        self.current = "h03-current"
        self.configuration["control_token"] = "must-not-enter"
        self.assertEqual(self.run_source()["execution_status"], "invalid_input")
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
