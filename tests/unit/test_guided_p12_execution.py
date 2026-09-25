"""Real learner subprocess and Context TCP; no Presidio/NeMo/AWS or grading claim."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient
import uvicorn

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs"
sys.path.insert(0, str(ROOT / "h12-protected-services"))
from context_server import create_app

spec = importlib.util.spec_from_file_location("p12_execution", ROOT / "h12-application-pipeline/execution.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

SOURCE = '''async def handle_request(request, services):
    if not await services.authenticate(request["credential"]):
        return {"status": 401, "text": ""}
    if not await services.authorize(request["tenant"]):
        return {"status": 403, "text": ""}
    text = await services.retrieve(request["message"])
    return {"status": 200 if text else 404, "text": text}
'''


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source_path = Path(self.temp.name) / "pipeline.py"
        self.source_path.write_text(SOURCE)
        self.suite, self.execution = str(uuid4()), str(uuid4())
        self.tokens = {role: "context-fixture-" + role for role in ("control", "service", "verifier")}
        self.app = create_app(database=Path(self.temp.name) / "context.sqlite3", tokens=self.tokens)
        self.api = TestClient(self.app)
        result = self.api.post("/v1/suites", headers=self.header("control"), json={
            "suite_id": self.suite, "execution_ids": [self.execution],
            "documents": [{"document_id": "account", "tenant": "team-a", "text": "계정 복구: 지원 담당자에게 문의하세요."}]})
        self.credentials = result.json()["credentials"]
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(128)
        self.server = uvicorn.Server(uvicorn.Config(self.app, log_level="critical", access_log=False))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.socket]}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        deadline = time.monotonic() + 5
        while not self.server.started and self.thread.is_alive() and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertTrue(self.server.started)
        self.configuration = {
            "suite_id": self.suite, "execution_id": self.execution,
            "origins": {"context": f"http://127.0.0.1:{self.socket.getsockname()[1]}",
                        "privacy": "http://unused.invalid", "nemo": "http://unused.invalid", "gateway": "http://unused.invalid"},
            "tokens": {"context": self.tokens["service"], "privacy": "unused-privacy", "nemo": "unused-nemo"},
            "capabilities": {role: (role + "-fixture-") * 5 for role in ("input_rail", "retrieval_rail", "output_rail", "main")}}
        self.request = {"credential": self.credentials["reader"], "tenant": "team-a", "message": "계정 복구"}

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=5)
        self.socket.close()
        self.assertFalse(self.thread.is_alive())

    def header(self, role):
        return {"Authorization": "Bearer " + self.tokens[role]}

    def run_source(self, source=None, **kwargs):
        if source is not None:
            self.source_path.write_text(source)
        return module.execute(self.source_path, self.request, self.configuration, **kwargs)

    def ledger(self):
        return self.api.get(f"/v1/suites/{self.suite}/ledger", headers=self.header("verifier")).json()

    def test_actual_function_calls_context_tcp_and_matches_ledger(self):
        result = self.run_source()
        self.assertEqual(result["execution_status"], "returned")
        self.assertEqual(result["source_digest"], hashlib.sha256(SOURCE.encode()).hexdigest())
        expected = "계정 복구: 지원 담당자에게 문의하세요."
        self.assertEqual(result["result"], {"status": 200, "text_digest": hashlib.sha256(expected.encode()).hexdigest(),
                                            "text_bytes": len(expected.encode())})
        ledger = self.ledger()
        self.assertEqual([row["stage"] for row in result["calls"]], ["authenticate", "authorize", "retrieval"])
        for actual, provider in zip(result["calls"], ledger["calls"]):
            self.assertEqual(actual["evidence"], provider["evidence"])
        raw = json.dumps(result, ensure_ascii=False)
        for private in (self.request["credential"], self.request["message"], expected):
            self.assertNotIn(private, raw)
        self.assertNotIn("task_completed", result)
        self.assertNotIn("security_verdict", result)

    def test_authentication_denial_stops_before_authorization(self):
        self.request["credential"] = "unknown-fixture-credential"
        result = self.run_source()
        self.assertEqual(result["result"]["status"], 401)
        self.assertEqual([call["stage"] for call in self.ledger()["calls"]], ["authenticate"])

    def test_authorization_denial_stops_before_retrieval(self):
        self.request["credential"] = self.credentials["visitor"]
        result = self.run_source()
        self.assertEqual(result["result"]["status"], 403)
        self.assertEqual([call["stage"] for call in self.ledger()["calls"]], ["authenticate", "authorize"])

    def test_empty_search_is_returned_as_not_found(self):
        self.request["message"] = "unmatchedfixture"
        result = self.run_source()
        self.assertEqual(result["result"]["status"], 404)
        self.assertEqual(result["result"]["text_bytes"], 0)

    def test_wrong_service_token_is_error_not_policy_denial(self):
        self.configuration["tokens"]["context"] = "wrong-fixture-service"
        result = self.run_source()
        self.assertEqual(result["execution_status"], "service_error")
        self.assertEqual(result["calls"][0]["http_status"], 401)
        self.assertEqual(result["calls"][0]["state"], "error")
        self.assertNotIn("result", result)

    def test_unfinished_and_syntax_error_do_not_call_services(self):
        for source, status in (("async def handle_request(request, services):\n    raise NotImplementedError\n", "not_implemented"),
                               ("def broken(\n", "runtime_error")):
            result = self.run_source(source)
            self.assertEqual(result["execution_status"], status)
            self.assertEqual(result["calls"], [])
        self.assertEqual(self.ledger()["calls"], [])

    def test_exception_and_print_do_not_disclose_credentials(self):
        result = self.run_source('async def handle_request(request, services):\n    print(request["credential"])\n    raise RuntimeError(request["credential"])\n')
        self.assertEqual(result["execution_status"], "runtime_error")
        self.assertNotIn(self.request["credential"], json.dumps(result))

    def test_worker_does_not_inherit_parent_credentials(self):
        source = 'import os\nasync def handle_request(request, services):\n    assert not any(k.startswith(("AWS_", "GUIDED_")) for k in os.environ)\n    return {"status": 403, "text": ""}\n'
        with patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "fixture-private", "GUIDED_CONTROL_TOKEN": "fixture-control"}):
            result = self.run_source(source)
        self.assertEqual(result["execution_status"], "returned")
        self.assertEqual(result["calls"], [])
        self.assertNotIn("task_completed", result)

    def test_whole_case_timeout_leaves_calls_unknown(self):
        source = "import time\nasync def handle_request(request, services):\n    time.sleep(5)\n"
        result = self.run_source(source, timeout=.2)
        self.assertEqual(result["execution_status"], "timeout")
        self.assertIsNone(result["calls"])

    def test_invalid_return_and_privileged_config_rejected(self):
        for value in ('{"status": True, "text": ""}', '{"status": 200, "text": ""}',
                      '{"status": 403, "text": "private"}', '{"status": 403, "text": "", "task_completed": True}'):
            result = self.run_source("async def handle_request(request, services):\n    return " + value + "\n")
            self.assertEqual(result["execution_status"], "invalid_return")
        self.configuration["tokens"]["control"] = "should-not-enter-worker"
        self.assertEqual(self.run_source()["execution_status"], "invalid_input")
        self.assertEqual(self.ledger()["calls"], [])

    def test_source_limit_and_current_legacy_source_not_implementation(self):
        self.assertEqual(self.run_source("#" * (module.SOURCE_LIMIT + 1))["execution_status"], "source_limit")
        result = module.execute(ROOT / "h12-application-pipeline/pipeline.py", self.request, self.configuration)
        self.assertEqual(result["execution_status"], "not_implemented")
        self.assertEqual(result["calls"], [])


if __name__ == "__main__":
    unittest.main()
