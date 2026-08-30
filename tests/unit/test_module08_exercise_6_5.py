from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "llm-security-control-plane" / "deploy" / "run-exercise-6-5.sh"
GUIDE = ROOT / "docs" / "MODULE08-EXERCISE-6.5.md"


class Module08Exercise65ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = SCRIPT.read_text(encoding="utf-8")
        cls.guide = GUIDE.read_text(encoding="utf-8")

    def test_builds_every_exercise_image_from_source(self) -> None:
        self.assertIn('bash "$ROOT/deploy/build-images.sh"', self.script)
        self.assertIn("examples/day6/nemo-guardrails", self.script)
        self.assertIn("examples/day6/presidio", self.script)
        self.assertIn("--build-only", self.script)
        self.assertIn("all six images built from the current checkout", self.script)

    def test_runs_the_progressive_deterministic_exercise(self) -> None:
        self.assertIn('bash "$ROOT/tests/e2e-learning-sequence.sh"', self.script)
        self.assertIn("module08-exercise-6.5=PASS", self.script)
        self.assertIn("28091 28092 28093 28094 28096", self.script)
        self.assertIn("`ss`(`iproute2`)", self.guide)

    def test_does_not_delete_unrelated_runtime(self) -> None:
        for unsafe in ("podman system prune", "podman volume prune", "podman rm -a"):
            self.assertNotIn(unsafe, self.script)

    def test_guide_has_build_run_observe_and_cleanup_contracts(self) -> None:
        for value in (
            "--build-only",
            "module08-exercise-6.5=BUILD_READY",
            "module08-learning-sequence=PASS",
            "application_decision",
            "upstream_called",
            "stage_order",
            "trap",
        ):
            self.assertIn(value, self.guide)


if __name__ == "__main__":
    unittest.main()
