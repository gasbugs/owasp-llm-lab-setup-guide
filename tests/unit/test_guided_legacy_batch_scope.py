"""Retired activities must not receive legacy completion or mutate old sources."""

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "e2e/run_guided_h01_h04_h21_h22_learner_fixes.py"
SPEC = importlib.util.spec_from_file_location("guided_legacy_batch", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LegacyBatchScopeTests(unittest.TestCase):
    def test_retired_activities_are_not_source_replacement_targets(self):
        self.assertEqual(set(MODULE.ACTIVITIES), {"H01", "H21", "H22"})
        for definition in MODULE.ACTIVITIES.values():
            self.assertNotIn("h02-document-ingestion", str(definition["path"]))
            self.assertNotIn("h03-ingestion-search", str(definition["path"]))
            self.assertNotIn("h04-bedrock-guardrail", str(definition["path"]))

    def test_unknown_activity_cannot_accept_a_pass_result(self):
        for activity in ("H02", "P02", "H03", "P03", "H04", "P04", "H99"):
            with self.subTest(activity=activity), self.assertRaises(ValueError):
                MODULE.assert_result(activity, {
                    "course_verdict": "PASS",
                    "verified_by": "guided-evidence-verifier",
                    "result": {},
                })

    def test_cli_rejects_retired_activity_before_any_execution(self):
        for activity in ("H02", "H03", "H04", "P04"):
            with self.subTest(activity=activity):
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "--activities", activity],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("invalid choice", result.stderr)

    def test_help_points_to_current_runners(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("check_guided_p02_live.py", result.stdout)
        self.assertIn("check_guided_p03_live.py", result.stdout)
        self.assertIn("check_guided_p04_live.py", result.stdout)


if __name__ == "__main__":
    unittest.main()
