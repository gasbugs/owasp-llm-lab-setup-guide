#!/usr/bin/env python3
"""Loopback regression tests for the common E2E chat transport contract."""

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


class _ScriptedServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, actions: list[dict[str, object]]):
        super().__init__(("127.0.0.1", 0), _ScriptedHandler)
        self.actions = actions
        self.request_count = 0
        self.count_lock = threading.Lock()


class _ScriptedHandler(BaseHTTPRequestHandler):
    server: _ScriptedServer

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)

        with self.server.count_lock:
            index = self.server.request_count
            self.server.request_count += 1

        if index < len(self.server.actions):
            action = self.server.actions[index]
        else:
            action = {
                "status": 500,
                "body": '{"error":"unexpected extra request"}',
            }

        delay = float(action.get("delay", 0))
        if delay:
            time.sleep(delay)

        status = int(action.get("status", 200))
        body_value = action.get("body", '{"reply":"FLAG"}')
        if isinstance(body_value, bytes):
            body = body_value
        else:
            body = str(body_value).encode("utf-8")

        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # Expected after the client intentionally times out.
            pass

    def log_message(self, _format: str, *_args: object) -> None:
        return


class CommonTransportRetryTests(unittest.TestCase):
    def _run_case(
        self,
        actions: list[dict[str, object]],
        *,
        trials: int = 1,
        expected_pattern: str = "FLAG",
        direct_chat: bool = False,
    ) -> dict[str, object]:
        server = _ScriptedServer(actions)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            with tempfile.TemporaryDirectory() as tmp:
                results = Path(tmp) / "results"
                env = os.environ.copy()
                origin = f"http://127.0.0.1:{server.server_address[1]}"
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
                if direct_chat:
                    command = 'source "$1"; chat "payload"'
                else:
                    command = (
                        'source "$1"; '
                        'run_payload_inline "CASE" "payload" "$2" "$3"'
                    )
                completed = subprocess.run(
                    [
                        "bash",
                        "-c",
                        command,
                        "transport-test",
                        str(COMMON),
                        expected_pattern,
                        str(trials),
                    ],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=15,
                )

                result_rows = []
                result_file = results / "results.jsonl"
                if result_file.exists():
                    result_rows = [
                        json.loads(line)
                        for line in result_file.read_text(encoding="utf-8").splitlines()
                    ]
                transport_rows = [
                    json.loads(path.read_text(encoding="utf-8"))
                    for path in sorted((results / "raw").glob("*.transport.json"))
                ] if (results / "raw").exists() else []
                automatic_transport_rows = [
                    json.loads(path.read_text(encoding="utf-8"))
                    for path in sorted((results / "raw").glob("chat-transport.*"))
                ] if (results / "raw").exists() else []
                index_file = results / "chat-transport.jsonl"
                transport_index = [
                    json.loads(line)
                    for line in index_file.read_text(encoding="utf-8").splitlines()
                ] if index_file.exists() else []
                raw_rows = {
                    path.name: path.read_text(encoding="utf-8").rstrip("\n")
                    for path in sorted((results / "raw").glob("*.txt"))
                } if (results / "raw").exists() else {}

                return {
                    "completed": completed,
                    "results": result_rows,
                    "transport": transport_rows,
                    "automatic_transport": automatic_transport_rows,
                    "transport_index": transport_index,
                    "raw": raw_rows,
                    "request_count": server.request_count,
                }
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_timeout_then_success_is_one_valid_trial_with_auditable_retry(self) -> None:
        case = self._run_case(
            [
                {"delay": 1.25, "body": '{"reply":"late FLAG"}'},
                {"body": '{"reply":"FLAG after retry"}'},
            ]
        )

        self.assertEqual(case["completed"].returncode, 0, case["completed"].stderr)
        self.assertEqual(case["request_count"], 2)
        result = case["results"][0]
        self.assertEqual((result["trials"], result["pass"], result["fail"]), (1, 1, 0))
        self.assertEqual(result["infra_fail"], 0)
        self.assertEqual(result["transport"]["attempts_total"], 2)
        self.assertEqual(result["transport"]["retries_total"], 1)

        transport = case["transport"][0]
        self.assertEqual(transport["attempt_count"], 2)
        self.assertEqual(transport["attempts"][0]["curl_rc"], 28)
        self.assertEqual(transport["attempts"][0]["http_status"], "000")
        self.assertTrue(transport["attempts"][0]["transport_error"])
        self.assertEqual(transport["final_outcome"], "valid_model_observation")

    def test_retryable_500_then_success_is_one_valid_trial(self) -> None:
        case = self._run_case(
            [
                {"status": 500, "body": '{"error":"temporary"}'},
                {"status": 200, "body": '{"reply":"FLAG"}'},
            ]
        )

        self.assertEqual(case["completed"].returncode, 0, case["completed"].stderr)
        self.assertEqual(case["request_count"], 2)
        result = case["results"][0]
        self.assertEqual((result["trials"], result["pass"], result["infra_fail"]), (1, 1, 0))
        transport = case["transport"][0]
        self.assertEqual(transport["attempts"][0]["http_status"], "500")
        self.assertEqual(transport["attempts"][0]["outcome"], "retryable_http_5xx")
        self.assertEqual(transport["attempts"][1]["http_status"], "200")

    def test_permanent_timeout_is_infra_after_bounded_attempts(self) -> None:
        case = self._run_case(
            [
                {"delay": 1.25, "body": '{"reply":"late one"}'},
                {"delay": 1.25, "body": '{"reply":"late two"}'},
            ]
        )

        self.assertEqual(case["completed"].returncode, 3)
        self.assertEqual(case["request_count"], 2)
        result = case["results"][0]
        self.assertEqual((result["trials"], result["pass"], result["fail"]), (1, 0, 0))
        self.assertEqual(result["infra_fail"], 1)
        self.assertEqual(result["transport"]["attempts_total"], 2)
        self.assertEqual(case["raw"]["CASE-trial-1.txt"], "ERR_INFRA")
        transport = case["transport"][0]
        self.assertFalse(transport["valid_model_observation"])
        self.assertEqual(transport["final_outcome"], "retryable_transport_error")

    def test_valid_model_failure_is_not_retried(self) -> None:
        case = self._run_case(
            [{"status": 200, "body": '{"reply":"request refused"}'}]
        )

        self.assertEqual(case["completed"].returncode, 0, case["completed"].stderr)
        self.assertEqual(case["request_count"], 1)
        result = case["results"][0]
        self.assertEqual((result["trials"], result["pass"], result["fail"]), (1, 0, 1))
        self.assertEqual(result["infra_fail"], 0)
        self.assertEqual(result["transport"]["retries_total"], 0)
        self.assertEqual(case["raw"]["CASE-trial-1.txt"], "request refused")

    def test_invalid_json_is_infra_and_is_not_retried(self) -> None:
        case = self._run_case([{"status": 200, "body": "not-json"}])

        self.assertEqual(case["completed"].returncode, 3)
        self.assertEqual(case["request_count"], 1)
        result = case["results"][0]
        self.assertEqual((result["pass"], result["fail"], result["infra_fail"]), (0, 0, 1))
        transport = case["transport"][0]
        self.assertEqual(transport["attempt_count"], 1)
        self.assertEqual(transport["final_outcome"], "invalid_json")
        self.assertFalse(transport["final"]["json_valid"])

    def test_empty_and_multiple_json_documents_are_infra(self) -> None:
        for label, body in (
            ("empty", ""),
            ("multiple", '{"reply":"FLAG"}\n{"reply":"FLAG"}'),
        ):
            with self.subTest(label=label):
                case = self._run_case([{"status": 200, "body": body}])
                self.assertEqual(case["completed"].returncode, 3)
                self.assertEqual(case["request_count"], 1)
                result = case["results"][0]
                self.assertEqual(
                    (result["pass"], result["fail"], result["infra_fail"]),
                    (0, 0, 1),
                )
                transport = case["transport"][0]
                self.assertEqual(transport["attempt_count"], 1)
                self.assertEqual(transport["final_outcome"], "invalid_json")
                self.assertFalse(transport["final"]["json_valid"])

    def test_http_200_error_object_is_infra_not_model_failure(self) -> None:
        case = self._run_case(
            [{"status": 200, "body": '{"error":"upstream unavailable"}'}]
        )

        self.assertEqual(case["completed"].returncode, 3)
        self.assertEqual(case["request_count"], 1)
        result = case["results"][0]
        self.assertEqual((result["pass"], result["fail"], result["infra_fail"]), (0, 0, 1))
        transport = case["transport"][0]
        self.assertEqual(transport["attempt_count"], 1)
        self.assertEqual(transport["final_outcome"], "invalid_response_contract")
        self.assertTrue(transport["final"]["json_valid"])
        self.assertFalse(transport["final"]["contract_valid"])

    def test_transport_attempts_never_inflate_trial_count(self) -> None:
        case = self._run_case(
            [
                {"status": 503, "body": '{"error":"busy"}'},
                {"body": '{"reply":"FLAG one"}'},
                {"body": '{"reply":"FLAG two"}'},
                {"body": '{"reply":"FLAG three"}'},
            ],
            trials=3,
        )

        self.assertEqual(case["completed"].returncode, 0, case["completed"].stderr)
        self.assertEqual(case["request_count"], 4)
        result = case["results"][0]
        self.assertEqual((result["trials"], result["pass"], result["fail"]), (3, 3, 0))
        self.assertEqual(result["infra_fail"], 0)
        self.assertEqual(len(result["transport"]["trials"]), 3)
        self.assertEqual(result["transport"]["attempts_total"], 4)
        self.assertEqual(result["transport"]["retries_total"], 1)

    def test_direct_chat_retry_creates_automatic_transport_evidence(self) -> None:
        case = self._run_case(
            [
                {"status": 503, "body": '{"error":"busy"}'},
                {"status": 200, "body": '{"reply":"FLAG"}'},
            ],
            direct_chat=True,
        )

        self.assertEqual(case["completed"].returncode, 0, case["completed"].stderr)
        self.assertEqual(case["completed"].stdout, "FLAG")
        self.assertEqual(case["request_count"], 2)
        self.assertEqual(len(case["automatic_transport"]), 1)
        evidence = case["automatic_transport"][0]
        self.assertTrue(evidence["evidence_auto_generated"])
        self.assertEqual((evidence["attempt_count"], evidence["retry_count"]), (2, 1))
        self.assertEqual(evidence["final"]["http_status"], "200")
        self.assertEqual(len(case["transport_index"]), 1)
        self.assertTrue(case["transport_index"][0]["evidence_file"].startswith("raw/"))


if __name__ == "__main__":
    unittest.main()
