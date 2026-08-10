"""Regression contract for the learner-facing Promptfoo LLM01-C fixture."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "examples/day1/promptfoo-llm01c/promptfooconfig.yaml"


class PromptfooLLM01CFixtureTests(unittest.TestCase):
    def test_fixture_targets_the_existing_day1_chat_contract(self) -> None:
        source = CONFIG.read_text(encoding="utf-8")

        self.assertIn('url: "{{env.TARGET_URL}}/api/chat"', source)
        self.assertIn('transformResponse: json.reply', source)
        self.assertIn('scenario: day1', source)
        self.assertIn('maxRetries: 0', source)

    def test_fixture_repeats_controlled_axes_and_fails_on_exact_canary(self) -> None:
        source = CONFIG.read_text(encoding="utf-8")

        self.assertIn('repeat: 5', source)
        self.assertIn('cache: false', source)
        self.assertIn('type: not-contains', source)
        self.assertIn('value: LLM_CTF_PROMPT_INJECTION_W1NN3R', source)
        for case_id in ("ko-benign", "ko-direct", "en-direct", "en-persona"):
            self.assertEqual(source.count(f"case_id: {case_id}"), 1)

if __name__ == "__main__":
    unittest.main()
