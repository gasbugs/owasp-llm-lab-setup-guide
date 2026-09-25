"""Real P04 worker and HTTP adapter with a local fixture, not AWS execution."""
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

import botocore.session
from botocore.validate import validate_parameters

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "llm-security-control-plane/guided-labs/h04-bedrock-guardrail"
spec = importlib.util.spec_from_file_location("p04_execution_test", LAB / "execution.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
IMPLEMENTATION = (ROOT / "tests/e2e/fixtures/p04_invoke_guarded.py").read_text()


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "learner.py"
        self.requests = []
        self.fault = None
        self.provider = {"ResponseMetadata": {"RequestId": "fixture-" + uuid4().hex},
                         "result": "fixture response, not an AWS verdict"}
        self.guardrail = {"guardrailIdentifier": "p04fixture", "guardrailVersion": "DRAFT"}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.requests.append((self.path, body))
                result = {key: body[key] for key in ("suite_id", "execution_id", "operation")}
                result["response"] = owner.provider
                if owner.fault == "binding":
                    result["execution_id"] = str(uuid4())
                raw = json.dumps(result).encode()
                if owner.fault == "size":
                    raw = b" " * 33000
                status = 502 if owner.fault == "error" else 302 if owner.fault == "redirect" else 200
                self.send_response(status)
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
                              "capability": "synthetic-p04-only-" * 3}

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def run_source(self, body=None, source=IMPLEMENTATION, **kwargs):
        self.source.write_text(source)
        if body is None:
            body = {"operation": "apply_guardrail", "text": " 정상 문장 "}
        return module.execute(self.source, body, self.guardrail, self.configuration, **kwargs)

    def test_each_operation_transmits_sdk_arguments_and_actual_response(self):
        model = botocore.session.get_session().get_service_model("bedrock-runtime")
        for operation, sdk_name in (("apply_guardrail", "ApplyGuardrail"), ("converse", "Converse")):
            with self.subTest(operation=operation):
                self.requests.clear()
                text = "  learner@example.com 테스트  "
                result = self.run_source({"operation": operation, "text": text})
                self.assertEqual(result["execution_status"], "returned")
                self.assertEqual(result["result"], self.provider)
                self.assertEqual(len(self.requests), 1)
                path, envelope = self.requests[0]
                self.assertEqual(path, "/v1/p04/invoke")
                self.assertEqual(envelope["operation"], operation)
                args = envelope["payload"]
                validate_parameters(args, model.operation_model(sdk_name).input_shape)
                if operation == "apply_guardrail":
                    self.assertEqual(args, {**self.guardrail, "source": "OUTPUT",
                        "content": [{"text": {"text": text}}], "outputScope": "FULL"})
                else:
                    self.assertEqual(args["guardrailConfig"], {**self.guardrail, "trace": "enabled"})
                    self.assertEqual(args["modelId"], "us.amazon.nova-lite-v1:0")
                    self.assertEqual(args["messages"], [{"role": "user", "content": [{"text": text}]}])
                    self.assertEqual(args["inferenceConfig"], {"maxTokens": 128, "temperature": 0.0})
                self.assertNotIn(self.configuration["capability"], json.dumps(result))
                self.assertNotIn("task_completed", result)

    def test_invalid_input_is_rejected_without_call(self):
        values = [
            {}, [], "text", True,
            {"operation": "unknown", "text": "hello"},
            {"operation": [], "text": "hello"},
            {"operation": "converse", "text": "hello", "guardrailIdentifier": "other"},
            *({"operation": "converse", "text": value} for value in
              ("", " \n ", "x" * 1001, 1, False, None, [], {})),
        ]
        for body in values:
            with self.subTest(body=body):
                self.assertEqual(self.run_source(body)["execution_status"], "rejected")
        self.assertEqual(self.requests, [])

    def test_text_boundaries_preserve_original(self):
        for text in ("x", "x" * 1000):
            self.assertEqual(self.run_source({"operation": "apply_guardrail", "text": text})[
                "execution_status"], "returned")
            self.assertEqual(self.requests[-1][1]["payload"]["content"][0]["text"]["text"], text)

    def test_provider_errors_redirect_mismatch_and_size_are_not_success(self):
        for fault in ("error", "redirect", "binding", "size"):
            with self.subTest(fault=fault):
                self.fault = fault
                self.requests.clear()
                result = self.run_source()
                self.assertEqual(result["execution_status"], "service_error")
                self.assertEqual(result["calls"][0]["state"], "error")
                self.assertEqual(len(self.requests), 1)

    def test_one_call_limit_prevents_second_network_request(self):
        source = '''
async def invoke_guarded(body, guardrail, services):
    await services.apply_guardrail(**guardrail)
    return await services.converse(**guardrail)
'''
        result = self.run_source(source=source)
        self.assertEqual(result["execution_status"], "service_error")
        self.assertEqual(len(self.requests), 1)
        self.assertEqual([row["state"] for row in result["calls"]], ["complete", "error"])

    def test_starter_syntax_and_wrong_return_have_no_calls(self):
        for source, status in (
            ((LAB / "learner.py").read_text(), "not_implemented"),
            ("def broken(:", "runtime_error"),
            ("async def invoke_guarded(*args): return None", "invalid_return"),
        ):
            self.assertEqual(self.run_source(source=source)["execution_status"], status)
        self.assertEqual(self.requests, [])

    def test_equivalent_implementation_and_comment_have_same_result_not_same_digest(self):
        alternate = IMPLEMENTATION.replace('identifier = guardrail["guardrailIdentifier"]',
                                           'identifier = guardrail.get("guardrailIdentifier")') + "\n# another implementation\n"
        first, second = self.run_source(), self.run_source(source=alternate)
        self.assertEqual(first["result"], second["result"])
        self.assertNotEqual(first["source_digest"], second["source_digest"])

    def test_no_parent_credentials_and_no_self_awarded_verdict(self):
        source = '''
import os
async def invoke_guarded(*args):
    if "P04_PARENT_SECRET" in os.environ:
        raise RuntimeError()
    return {"fixture": "constant"}
'''
        with patch.dict(os.environ, {"P04_PARENT_SECRET": "not-for-worker"}):
            result = self.run_source(source=source)
        self.assertEqual(result["execution_status"], "returned")
        self.assertEqual(result["calls"], [])
        self.assertNotIn("task_completed", result)
        self.assertNotIn("security_verdict", result)

    def test_bounds_and_timeout_do_not_infer_zero_calls(self):
        self.assertEqual(self.run_source(source="#" * 65537)["execution_status"], "source_limit")
        result = self.run_source(source="async def invoke_guarded(*args):\n    while True: pass", timeout=.2)
        self.assertEqual(result["execution_status"], "timeout")
        self.assertIsNone(result["calls"])
        self.assertEqual(self.run_source({"text": "x" * 65536})["execution_status"], "input_limit")

    def test_invalid_server_reference_and_extra_credentials_stop_before_worker(self):
        for guardrail in ({}, {"guardrailIdentifier": "", "guardrailVersion": "DRAFT"},
                          {"guardrailIdentifier": "fixture", "guardrailVersion": "latest"}):
            self.guardrail = guardrail
            self.assertEqual(self.run_source()["execution_status"], "invalid_input")
        self.configuration["control_token"] = "must-not-enter"
        self.assertEqual(self.run_source()["execution_status"], "invalid_input")
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
