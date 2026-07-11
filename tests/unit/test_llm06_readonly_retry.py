#!/usr/bin/env python3
"""Regression tests for the LLM06 read-only-only retry boundary."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "tests" / "e2e" / "lib" / "common.sh"
LLM06 = ROOT / "tests" / "e2e" / "llm06" / "test_llm06_agency.sh"
VALID = '{"reply":"READ_ONLY_OK","trace":[],"user":"farmer1"}'


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, actions: list[dict[str, object]]):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.actions = actions
        self.request_count = 0
        self.lock = threading.Lock()


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with self.server.lock:
            index = self.server.request_count
            self.server.request_count += 1
        action = self.server.actions[index]
        delay = float(action.get("delay", 0))
        if delay:
            time.sleep(delay)
        body = str(action.get("body", VALID)).encode()
        try:
            self.send_response(int(action.get("status", 200)))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, _format: str, *_args: object) -> None:
        return


class Llm06ReadonlyRetryTests(unittest.TestCase):
    def _run(self, actions: list[dict[str, object]]) -> dict[str, object]:
        server = _Server(actions)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                results = Path(tmp) / "results"
                origin = f"http://127.0.0.1:{server.server_address[1]}"
                env = os.environ.copy()
                env.update(
                    {
                        "TARGET_URL": origin,
                        "AGENT_URL": origin,
                        "RESULTS_DIR": str(results),
                        "CHAT_REQUEST_TIMEOUT": "1",
                        "CHAT_MAX_ATTEMPTS": "2",
                        "CHAT_RETRY_DELAY_SECONDS": "0",
                    }
                )
                completed = subprocess.run(
                    [
                        "bash",
                        "-c",
                        'source "$1"; chat_agent_readonly "list only" farmer1 '
                        '"$RESULTS_DIR/readonly.transport.json"',
                        "llm06-readonly-test",
                        str(COMMON),
                    ],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
                evidence_path = results / "readonly.transport.json"
                evidence_text = evidence_path.read_text() if evidence_path.exists() else ""
                return {
                    "completed": completed,
                    "count": server.request_count,
                    "evidence": json.loads(evidence_text) if evidence_text else None,
                    "evidence_text": evidence_text,
                }
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_timeout_then_success_is_one_observation_with_two_attempts(self) -> None:
        case = self._run(
            [
                {"delay": 1.2, "body": VALID},
                {"body": VALID},
            ]
        )
        self.assertEqual(case["completed"].returncode, 0, case["completed"].stderr)
        self.assertEqual(case["completed"].stdout, VALID)
        self.assertEqual(case["count"], 2)
        self.assertEqual(case["evidence"]["attempt_count"], 2)
        self.assertEqual(case["evidence"]["retry_count"], 1)
        self.assertEqual(case["evidence"]["attempts"][0]["curl_rc"], 28)
        self.assertNotIn("READ_ONLY_OK", case["evidence_text"])

    def test_retryable_503_then_success(self) -> None:
        case = self._run(
            [
                {"status": 503, "body": '{"error":"busy"}'},
                {"body": VALID},
            ]
        )
        self.assertEqual(case["completed"].returncode, 0, case["completed"].stderr)
        self.assertEqual(case["count"], 2)
        self.assertEqual(
            case["evidence"]["attempts"][0]["outcome"], "retryable_http_5xx"
        )
        self.assertTrue(case["evidence"]["valid_agent_observation"])

    def test_malformed_200_fails_closed_without_retry(self) -> None:
        for body in ("not-json", '{"reply":"missing trace and user"}'):
            with self.subTest(body=body):
                case = self._run([{"body": body}])
                self.assertEqual(case["completed"].returncode, 1)
                self.assertEqual(case["count"], 1)
                self.assertEqual(case["evidence"]["attempt_count"], 1)
                self.assertFalse(case["evidence"]["valid_agent_observation"])

    def test_delete_path_is_single_send_and_only_max_step_uses_retry(self) -> None:
        common = COMMON.read_text(encoding="utf-8")
        single_send = common.split("chat_agent() {", 1)[1].split(
            "# chat_agent_readonly <", 1
        )[0]
        self.assertEqual(single_send.count("curl -fsS"), 1)
        self.assertNotIn("CHAT_MAX_ATTEMPTS", single_send)

        llm06 = LLM06.read_text(encoding="utf-8")
        measure = llm06.split("measure_tool_path() {", 1)[1].split(
            "test_max_step_contract() {", 1
        )[0]
        self.assertIn('resp=$(chat_agent "$msg" "farmer1")', measure)
        self.assertNotIn("chat_agent_readonly", measure)
        self.assertIn('"A4-delete-animal-last"', llm06)

        max_step = llm06.split("test_max_step_contract() {", 1)[1].split(
            "test_tool_catalog_contract", 1
        )[0]
        self.assertIn("chat_agent_readonly", max_step)


if __name__ == "__main__":
    unittest.main()
