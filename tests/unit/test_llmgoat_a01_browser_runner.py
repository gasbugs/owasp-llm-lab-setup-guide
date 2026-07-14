"""Static and CLI contracts for the instructor-only LLMGoat A01 runner."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BROWSER_DIR = ROOT / "tests" / "browser"
RUNNER = BROWSER_DIR / "run_llmgoat_a01_ui.py"
README = ROOT / "tests" / "browser" / "README.md"
sys.path.insert(0, str(BROWSER_DIR))
SPEC = importlib.util.spec_from_file_location("llmgoat_a01_ui_runner", RUNNER)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LlmgoatA01BrowserRunnerTest(unittest.TestCase):
    def test_help_is_offline_and_exposes_only_the_llmgoat_target(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(RUNNER), "--help"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--llmgoat-url", completed.stdout)
        self.assertNotIn("--rag-url", completed.stdout)
        self.assertNotIn("--dvla-url", completed.stdout)

    def test_runner_uses_shared_browser_probe_and_writes_evidence(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('DEFAULT_LLMGOAT_URL = "http://127.0.0.1:15000"', source)
        self.assertIn("evidence = run_llmgoat(", source)
        self.assertIn('result_dir / "network-events.json"', source)
        self.assertIn('result_dir / "sha256sums.json"', source)
        self.assertIn('result_dir / "result.json"', source)
        self.assertIn("for line in format_llmgoat_course_output(evidence):", source)
        self.assertIn('print(f"RESULT_DIR={result_dir}")', source)

    def test_dom_failure_preserves_captured_a01_request_count(self) -> None:
        origin = "http://127.0.0.1:15000"
        records = [
            {
                "event": "request",
                "method": "POST",
                "url": origin + "/api/a01-prompt-injection",
            },
            {
                "event": "request",
                "method": "GET",
                "url": origin + "/challenges/a01-prompt-injection",
            },
        ]
        count = MODULE.observed_a01_request_count(records, origin)
        evidence = MODULE.failure_evidence("DOM step failed", request_count=count)
        self.assertEqual(count, 1)
        self.assertEqual(evidence["request_count"], 1)
        self.assertEqual(
            MODULE.format_llmgoat_course_output(evidence)[0],
            "API request count: 1",
        )

    def test_readme_has_copy_paste_install_forward_and_run_commands(self) -> None:
        text = README.read_text(encoding="utf-8")
        self.assertIn("python -m pip install -r tests/browser/requirements.txt", text)
        self.assertIn("infrastructure/scripts/student/instance-id.sh", text)
        self.assertNotIn("Reservations[].Instances[] | [0].InstanceId", text)
        self.assertIn('.venv/bin/activate', text)
        self.assertNotIn('.venv-browser', text)
        self.assertIn('"portNumber":["5000"]', text)
        self.assertIn("python tests/browser/run_llmgoat_a01_ui.py", text)
        self.assertIn("has not yet been live-run", text)


if __name__ == "__main__":
    unittest.main()
