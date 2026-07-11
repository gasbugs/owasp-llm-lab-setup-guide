"""Offline and loopback integration contracts for complete LLMGoat validation."""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
LLMGOAT = ROOT / "tests" / "e2e" / "llmgoat"


DEFAULT_REVIEWS = {
    "Alpine Goat": ["a1", "a2", "a3", "a4"],
    "Boer Goat": ["b1", "b2", "b3", "b4"],
    "Pygmy Goat": ["p1", "p2", "p3", "p4"],
}
VECTOR_KEYS = (
    "Grace Goatper",
    "Isaac Chewton",
    "Leonardo Da Vinchevre",
    "Aristogoatle",
    "Beethohoof",
    "Neil Armstrongut",
    "Julius Cheesar",
    "Houdini the Goatini",
    "Flag",
)


def default_vectors() -> dict[str, list[Any]]:
    result: dict[str, list[Any]] = {
        key: [float(index + 1)] * 32 for index, key in enumerate(VECTOR_KEYS)
    }
    result["Flag"] = ["a"] * 32
    return result


class FakeLlmgoat:
    def __init__(
        self,
        *,
        fail_add_review: bool = False,
        block_add_review: bool = False,
        fail_cleanup_reset: bool = False,
        malformed_challenge_body=None,
    ) -> None:
        self.reviews = json.loads(json.dumps(DEFAULT_REVIEWS))
        self.vectors = default_vectors()
        self.fail_add_review = fail_add_review
        self.block_add_review = block_add_review
        self.fail_cleanup_reset = fail_cleanup_reset
        self.cleanup_reset_armed = False
        self.malformed_challenge_body = malformed_challenge_body
        self.review_added = threading.Event()
        self.release_add_review = threading.Event()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, payload: Any, status: int = 200) -> None:
                body = json.dumps(payload, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self) -> bytes:
                return self.rfile.read(int(self.headers.get("Content-Length", "0")))

            def _send_raw(self, body: bytes, status: int = 200) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802 - stdlib server hook
                if self.path == "/api/model_status":
                    self._send({"model_busy": False})
                elif self.path.endswith("/get_reviews"):
                    self._send(owner.reviews)
                elif self.path.endswith("/export_vectors"):
                    self._send(owner.vectors)
                elif self.path.endswith("/reset_vectors"):
                    owner.vectors = default_vectors()
                    self._send({"status": "Vectors reset to default"})
                else:
                    self._send({"error": "not found"}, 404)

            def do_POST(self) -> None:  # noqa: N802 - stdlib server hook
                body = self._body()
                if self.path.endswith("/reset_reviews"):
                    if owner.cleanup_reset_armed:
                        owner.cleanup_reset_armed = False
                        self._send({"error": "injected reset failure"}, 500)
                        return
                    owner.reviews = json.loads(json.dumps(DEFAULT_REVIEWS))
                    self._send({"success": True, "reviews": owner.reviews})
                    return
                if self.path.endswith("/add_review"):
                    payload = json.loads(body)
                    owner.reviews.setdefault(payload["goat"], []).append(payload["review"])
                    owner.review_added.set()
                    if owner.block_add_review:
                        owner.block_add_review = False
                        owner.release_add_review.wait(timeout=10)
                    if owner.fail_add_review:
                        owner.fail_add_review = False
                        owner.cleanup_reset_armed = owner.fail_cleanup_reset
                        self._send({"error": "injected review-store failure"}, 500)
                        return
                    self._send({"success": True})
                    return
                if self.path.endswith("/import_vectors"):
                    match = re.search(br"\r\n\r\n(.*)\r\n--[^\r\n]+--\r\n?$", body, re.S)
                    if match is None:
                        self._send({"error": "bad multipart"}, 400)
                        return
                    owner.vectors = json.loads(match.group(1))
                    self._send({"status": "Vectors updated"})
                    return
                if self.path.startswith("/api/a"):
                    if owner.malformed_challenge_body is not None:
                        self._send_raw(owner.malformed_challenge_body)
                        return
                    self._send({"response": "model outcome observed", "solved": False})
                    return
                self._send({"error": "not found"}, 404)

            def log_message(self, _format: str, *args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self) -> "FakeLlmgoat":
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class LlmgoatShellContractTest(unittest.TestCase):
    def test_all_shell_entrypoints_parse(self) -> None:
        for name in (
            "lib.sh",
            "run-all.sh",
            "test_a01_prompt_injection.sh",
            "test_a02_a04_a06_a08.sh",
        ):
            result = subprocess.run(
                ["bash", "-n", str(LLMGOAT / name)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, f"{name}: {result.stderr}")

    def test_loopback_raw_evidence_and_outcome_policies_are_explicit(self) -> None:
        library = (LLMGOAT / "lib.sh").read_text(encoding="utf-8")
        runner = (LLMGOAT / "run-all.sh").read_text(encoding="utf-8")
        mutable = (LLMGOAT / "test_a02_a04_a06_a08.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("require_loopback_url.py", library)
        self.assertIn("curl --noproxy '*'", library)
        self.assertIn("raw/requests.jsonl", library)
        self.assertIn('outcome_policy:"observation-only"', library)
        self.assertNotIn("/tmp/goat-cookies", library)
        self.assertIn("reset_reviews", mutable)
        self.assertIn("reset_vectors", mutable)
        self.assertIn('"$A08_BEFORE_SHA" != "$A08_RESTORED_SHA"', mutable)
        self.assertIn("deterministic-contract", mutable)
        self.assertIn("mutable_state:\"deterministic-fail-closed\"", runner)
        self.assertIn("trap 'goat_exit_on_signal 143' TERM", library)

    def test_full_cycle_runs_llmgoat_before_final_llm10(self) -> None:
        source = (ROOT / "tests" / "e2e" / "run-full-cycle.sh").read_text(
            encoding="utf-8"
        )
        invocation = source.index("\nrun_llmgoat\n")
        final_day = source.index("\nif require_day_ready day5; then", invocation)
        self.assertLess(invocation, final_day)
        self.assertIn('FAILED_STEPS+=("e2e:llmgoat")', source)

    def test_run_all_against_loopback_contract_server(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, FakeLlmgoat() as fake:
            result_dir = Path(temporary) / "evidence"
            environment = {
                **os.environ,
                "GOAT_URL": fake.url,
                "RESULTS_DIR": str(result_dir),
                "TRIALS": "1",
                "GOAT_REQUEST_TIMEOUT": "10",
            }
            result = subprocess.run(
                ["bash", str(LLMGOAT / "run-all.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            summary = json.loads((result_dir / "summary.json").read_text())
            self.assertEqual(summary["status"], "PASS")
            self.assertEqual(summary["counts"]["observations"], 9)
            self.assertEqual(summary["counts"]["state_contracts"], 2)
            rows = [
                json.loads(line)
                for line in (result_dir / "results.jsonl").read_text().splitlines()
            ]
            self.assertEqual(len(rows), 9)
            self.assertTrue(all(row["infra_fail"] == 0 for row in rows))
            self.assertTrue(all(row["verdict"] == "OBSERVED" for row in rows))
            self.assertFalse((result_dir / ".cookies").exists())

    def test_failure_after_mutation_runs_registered_reset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, FakeLlmgoat(
            fail_add_review=True
        ) as fake:
            result_dir = Path(temporary) / "failure-evidence"
            environment = {
                **os.environ,
                "GOAT_URL": fake.url,
                "RESULTS_DIR": str(result_dir),
                "TRIALS": "1",
                "GOAT_REQUEST_TIMEOUT": "10",
            }
            result = subprocess.run(
                ["bash", str(LLMGOAT / "test_a02_a04_a06_a08.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(fake.reviews, DEFAULT_REVIEWS)
            self.assertFalse((result_dir / ".cookies").exists())
            raw_rows = [
                json.loads(line)
                for line in (result_dir / "raw" / "requests.jsonl")
                .read_text()
                .splitlines()
            ]
            failed_add = next(
                row for row in raw_rows if row["evidence_id"] == "a04-add-poison-1"
            )
            self.assertFalse(failed_add["infra_ok"])
            self.assertEqual(failed_add["transport"]["http_status"], "500")
            self.assertEqual(raw_rows[-1]["evidence_id"], "a04-trap-reset")
            self.assertTrue(raw_rows[-1]["infra_ok"])

    def test_term_after_mutation_runs_registered_reset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, FakeLlmgoat(
            block_add_review=True
        ) as fake:
            result_dir = Path(temporary) / "signal-evidence"
            environment = {
                **os.environ,
                "GOAT_URL": fake.url,
                "RESULTS_DIR": str(result_dir),
                "TRIALS": "1",
                "GOAT_REQUEST_TIMEOUT": "10",
            }
            process = subprocess.Popen(
                ["bash", str(LLMGOAT / "test_a02_a04_a06_a08.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                self.assertTrue(
                    fake.review_added.wait(timeout=10),
                    "A04 review mutation was not reached",
                )
                process.send_signal(signal.SIGTERM)
                fake.release_add_review.set()
                stdout, stderr = process.communicate(timeout=20)
            finally:
                fake.release_add_review.set()
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
            self.assertEqual(process.returncode, 143, stdout + stderr)
            self.assertEqual(fake.reviews, DEFAULT_REVIEWS)
            self.assertFalse((result_dir / ".cookies").exists())
            raw_rows = [
                json.loads(line)
                for line in (result_dir / "raw" / "requests.jsonl")
                .read_text()
                .splitlines()
            ]
            self.assertEqual(raw_rows[-1]["evidence_id"], "a04-trap-reset")
            self.assertTrue(raw_rows[-1]["infra_ok"])

    def test_cleanup_http_failure_still_removes_cookie_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, FakeLlmgoat(
            fail_add_review=True, fail_cleanup_reset=True
        ) as fake:
            result_dir = Path(temporary) / "cleanup-failure-evidence"
            environment = {
                **os.environ,
                "GOAT_URL": fake.url,
                "RESULTS_DIR": str(result_dir),
                "TRIALS": "1",
                "GOAT_REQUEST_TIMEOUT": "10",
            }
            result = subprocess.run(
                ["bash", str(LLMGOAT / "test_a02_a04_a06_a08.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotEqual(fake.reviews, DEFAULT_REVIEWS)
            self.assertFalse((result_dir / ".cookies").exists())
            raw_rows = [
                json.loads(line)
                for line in (result_dir / "raw" / "requests.jsonl")
                .read_text()
                .splitlines()
            ]
            self.assertEqual(raw_rows[-1]["evidence_id"], "a04-trap-reset")
            self.assertFalse(raw_rows[-1]["infra_ok"])
            self.assertEqual(raw_rows[-1]["transport"]["http_status"], "500")

    def test_empty_and_multi_document_json_fail_closed(self) -> None:
        malformed_bodies = (
            b"",
            b'{"response":"x","solved":false}\n'
            b'{"response":"y","solved":false}\n',
        )
        for index, body in enumerate(malformed_bodies):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                with FakeLlmgoat(malformed_challenge_body=body) as fake:
                    result_dir = Path(temporary) / "malformed-evidence"
                    environment = {
                        **os.environ,
                        "GOAT_URL": fake.url,
                        "RESULTS_DIR": str(result_dir),
                        "TRIALS": "1",
                        "GOAT_REQUEST_TIMEOUT": "10",
                    }
                    result = subprocess.run(
                        ["bash", str(LLMGOAT / "test_a01_prompt_injection.sh")],
                        cwd=ROOT,
                        env=environment,
                        text=True,
                        capture_output=True,
                        check=False,
                        timeout=30,
                    )
                    self.assertNotEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )
                    self.assertFalse((result_dir / ".cookies").exists())
                    raw_rows = [
                        json.loads(line)
                        for line in (result_dir / "raw" / "requests.jsonl")
                        .read_text()
                        .splitlines()
                    ]
                    failed = raw_rows[-1]
                    self.assertFalse(failed["infra_ok"])
                    self.assertFalse(failed["response"]["json_valid"])


if __name__ == "__main__":
    unittest.main()
