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

    def test_builds_current_source_and_accepts_learner_policy(self) -> None:
        self.assertIn("--build-only", self.script)
        self.assertIn("--policy-file", self.script)
        self.assertIn('bash "$ROOT/deploy/build-images.sh"', self.script)
        self.assertIn("control-plane images built from source", self.script)

    def test_checks_the_exact_serial_policy_solution(self) -> None:
        for value in (
            "input:prohibited:EMAIL_ADDRESS",
            '.guardrail.stage_order == ["presidio_input"]',
            ".guardrail.guard_model_calls == 0",
            'index("bedrock_main")',
            'index("EMAIL_ADDRESS")',
            "module08-exercise-6.5=PASS",
        ):
            self.assertIn(value, self.script)

    def test_isolated_runtime_is_cleaned_without_broad_deletion(self) -> None:
        for value in (
            "module08-exercise-65-bedrock",
            "module08-exercise-65-spoke",
            "module08-exercise-65-hub",
            "trap cleanup EXIT",
            "MODULE08_65_EVIDENCE_DIR",
        ):
            self.assertIn(value, self.script)
        for unsafe in ("podman system prune", "podman volume prune", "podman rm -a"):
            self.assertNotIn(unsafe, self.script)

    def test_guide_preserves_learner_authorship(self) -> None:
        self.assertIn("06.5-serial-guardrail-review-exercise.md", self.guide)
        self.assertIn("정책을 대신 수정하지 않습니다", self.guide)
        self.assertIn("앞 차시의 실행 상태나 AWS 자원 없이", self.guide)


if __name__ == "__main__":
    unittest.main()
