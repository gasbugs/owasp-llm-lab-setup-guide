"""Real child function and HTTP calls against a local protocol fixture, not AWS."""
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

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs/h02-document-ingestion"
spec = importlib.util.spec_from_file_location("p02_execution", ROOT / "execution.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

IMPLEMENTATION = '''
async def prepare_document(body, document_id, services):
    if not isinstance(body, dict) or set(body) != {"title", "body"}:
        raise ValueError()
    title, text = body["title"], body["body"]
    if not isinstance(title, str) or not 1 <= len(title) <= 120 or not title.strip() or "\\n" in title or "\\r" in title:
        raise ValueError()
    if not isinstance(text, str) or not 10 <= len(text) <= 4000 or not text.strip():
        raise ValueError()
    source = await services.store_source(f"h02/knowledge/{document_id}.md", f"# {title}\\n\\n{text}\\n")
    embedding = await services.embed(text)
    return {"source": source, "embedding": embedding}
'''


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "learner.py"
        self.requests = []
        self.fault = None
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.requests.append({"path": self.path, "body": body, "authorization": self.headers.get("Authorization")})
                response = {key: body[key] for key in ("suite_id", "execution_id", "operation")}
                response["response"] = {"provider_request_id": body["operation"] + "-fixture"}
                if owner.fault == "binding":
                    response["execution_id"] = str(uuid4())
                raw = json.dumps(response).encode()
                if owner.fault == "size":
                    raw = b" " * 20000
                status = 502 if owner.fault == "error" else 302 if owner.fault == "redirect" else 200
                self.send_response(status)
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Content-Type", "application/json")
                if status == 302:
                    self.send_header("Location", owner.configuration["origin"] + "/unexpected")
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.configuration = {"suite_id": str(uuid4()), "execution_id": str(uuid4()),
                              "origin": f"http://127.0.0.1:{self.server.server_port}", "capability": "synthetic-token-" * 4}
        self.body = {"title": "운영 안내", "body": "합성 원문을 저장하는 연습입니다."}

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def execute(self, source=IMPLEMENTATION, body=None, **kwargs):
        self.source.write_text(source)
        return module.execute(self.source, self.body if body is None else body, self.configuration, **kwargs)

    def test_actual_function_makes_two_http_calls_with_original_input(self):
        result = self.execute()
        self.assertEqual(result["execution_status"], "returned")
        self.assertEqual([r["body"]["operation"] for r in self.requests], ["store_source", "embed"])
        self.assertEqual(self.requests[0]["body"]["payload"], {
            "key": f"h02/knowledge/{self.configuration['execution_id']}.md",
            "content": "# 운영 안내\n\n합성 원문을 저장하는 연습입니다.\n"})
        self.assertEqual(self.requests[1]["body"]["payload"], {"text": self.body["body"]})
        self.assertEqual(result["result"], {"source": {"provider_request_id": "store_source-fixture"},
                                            "embedding": {"provider_request_id": "embed-fixture"}})
        self.assertTrue(all(r["path"] == "/v1/p02/invoke" for r in self.requests))
        self.assertNotIn(self.configuration["capability"], json.dumps(result))
        self.assertNotIn("task_completed", result)

    def test_different_valid_function_and_comment_keep_behavior(self):
        alternative = IMPLEMENTATION.replace('title, text = body["title"], body["body"]',
                                               'text = body["body"]; title = body["title"]') + "\n# harmless edit\n"
        first, second = self.execute(), self.execute(alternative)
        self.assertEqual(first["result"], second["result"])
        self.assertNotEqual(first["source_digest"], second["source_digest"])
        self.assertEqual(len(self.requests), 4)

    def test_invalid_payload_is_rejected_by_learner_without_calls(self):
        for body in ({}, {**self.body, "object_key": "untrusted"}, {**self.body, "body": ""},
                     {**self.body, "title": "bad\nheading"}, {**self.body, "body": True}, [self.body]):
            self.assertEqual(self.execute(body=body)["execution_status"], "rejected")
        self.assertEqual(self.requests, [])

    def test_starter_syntax_failure_and_invalid_return_are_distinct(self):
        cases = ((ROOT.joinpath("learner.py").read_text(), "not_implemented"),
                 ("def broken(:", "runtime_error"),
                 ("async def prepare_document(*args): return 1", "invalid_return"))
        for source, status in cases:
            self.assertEqual(self.execute(source)["execution_status"], status)
        self.assertEqual(self.requests, [])

    def test_gateway_failure_binding_redirect_size_stop_before_embedding(self):
        for fault in ("error", "binding", "redirect", "size"):
            self.requests.clear()
            self.fault = fault
            result = self.execute()
            self.assertEqual(result["execution_status"], "service_error")
            self.assertEqual(len(self.requests), 1)
            self.assertEqual(result["calls"][0]["state"], "error")

    def test_deny_all_and_hardcoded_return_are_not_automatically_graded(self):
        denied = self.execute("async def prepare_document(*args): raise ValueError()")
        fixed = self.execute('async def prepare_document(*args): return {"source": {}, "embedding": {}}')
        self.assertEqual(denied["execution_status"], "rejected")
        self.assertEqual(fixed["execution_status"], "returned")
        self.assertEqual(fixed["calls"], [])
        self.assertNotIn("task_completed", fixed)
        self.assertEqual(self.requests, [])

    def test_parent_credentials_are_not_in_worker_environment(self):
        source = '''
import os
async def prepare_document(*args):
    if "P02_PARENT_SECRET" in os.environ:
        raise RuntimeError()
    return {"source": {}, "embedding": {}}
'''
        with patch.dict(os.environ, {"P02_PARENT_SECRET": "must-not-inherit"}):
            self.assertEqual(self.execute(source)["execution_status"], "returned")

    def test_timeout_and_size_limits_have_unknown_calls(self):
        result = self.execute("async def prepare_document(*args):\n    while True: pass", timeout=0.2)
        self.assertEqual(result["execution_status"], "timeout")
        self.assertIsNone(result["calls"])
        result = self.execute("#" * 65537)
        self.assertEqual(result["execution_status"], "source_limit")
        self.assertIsNone(result["source_digest"])

    def test_lifecycle_credentials_cannot_enter_configuration(self):
        self.configuration["control_token"] = "not-for-worker"
        self.assertEqual(self.execute()["execution_status"], "invalid_input")
        self.assertEqual(self.requests, [])

    def test_configuration_or_import_error_is_not_learner_input_rejection(self):
        self.assertEqual(self.execute("raise ValueError('import failed')")["execution_status"], "runtime_error")
        self.configuration["origin"] = "file:///wrong"
        self.assertEqual(self.execute()["execution_status"], "runtime_error")
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
