"""Strict offline contracts for the ten LLMGoat learner writeups."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests" / "e2e" / "llmgoat" / "solution_cases.py"
SPEC = importlib.util.spec_from_file_location("llmgoat_solution_cases", SOURCE)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LlmgoatSolutionCaseTest(unittest.TestCase):
    def test_every_challenge_has_one_baseline_and_one_solution(self) -> None:
        expected = {
            f"a{number:02d}-{suffix}"
            for number in range(1, 11)
            for suffix in ("baseline", "solution")
        }
        self.assertEqual(set(MODULE.CASES), expected)
        self.assertEqual(set(MODULE.TARGETS), {f"a{number:02d}" for number in range(1, 11)})

    def test_a10_fixture_contains_exactly_31_explicit_calls(self) -> None:
        text = MODULE.CASES["a10-solution"]["text"]
        self.assertEqual(text.splitlines().count('get_order("0")'), 31)
        self.assertNotIn("through 1031", text)

    def test_success_requires_target_and_boolean_solved_true(self) -> None:
        accepted = MODULE.classify(
            "a03",
            {"response": "FLAG{Baaaaaaaaaaaaad_Goat}", "solved": True},
        )
        missing_target = MODULE.classify(
            "a03", {"response": "plugin returned a value", "solved": True}
        )
        false_solved = MODULE.classify(
            "a03",
            {"response": "FLAG{Baaaaaaaaaaaaad_Goat}", "solved": False},
        )
        self.assertTrue(accepted["accepted"])
        self.assertEqual(accepted["classification"], "HIT")
        self.assertFalse(missing_target["accepted"])
        self.assertEqual(missing_target["classification"], "ERR")
        self.assertFalse(false_solved["accepted"])
        self.assertEqual(false_solved["classification"], "ERR")

    def test_case_insensitive_challenges_still_require_exact_phrase(self) -> None:
        for challenge, response in (
            ("a04", "space chicken"),
            ("a09", "The picture contains a Cyborg Goat."),
        ):
            with self.subTest(challenge=challenge):
                self.assertTrue(
                    MODULE.classify(
                        challenge, {"response": response, "solved": True}
                    )["accepted"]
                )


if __name__ == "__main__":
    unittest.main()
