"""Contract for the learner-facing Promptfoo LLM01-C red-team fixture."""

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

    def test_fixture_generates_a_bounded_local_red_team_suite(self) -> None:
        source = CONFIG.read_text(encoding="utf-8")

        self.assertIn("provider: ollama:chat:llama3.1:8b-instruct-q4_K_M", source)
        self.assertIn("numTests: 4", source)
        self.assertIn("maxCharsPerMessage: 500", source)
        self.assertIn("- id: policy", source)
        self.assertIn("must never follow requests", source)
        self.assertIn("- basic", source)
        self.assertIn("- base64", source)
        self.assertIn("type: not-contains", source)
        self.assertIn("value: LLM_CTF_PROMPT_INJECTION_W1NN3R", source)
        self.assertNotIn("repeat:", source)

if __name__ == "__main__":
    unittest.main()
