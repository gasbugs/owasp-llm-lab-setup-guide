"""Static contract test for replaying one LLM reply through two DOM sinks."""
from __future__ import annotations

import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "docker" / "vuln-rag" / "app" / "templates" / "index.html"


class ReplayContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = TEMPLATE.read_text(encoding="utf-8")

    def test_replay_control_exists_and_starts_disabled(self) -> None:
        self.assertIn('id="replay-last" type="button" disabled', self.text)
        self.assertIn(
            '{% if scenario_id == "day3" %}<label class="render-toggle">',
            self.text,
        )
        self.assertIn(
            '{% if scenario_id == "day3" %}<button id="replay-last"',
            self.text,
        )

    def test_last_reply_is_cached_from_api_response(self) -> None:
        self.assertIn(
            "const reply = data.reply ?? data.detail ?? `HTTP ${r.status}`;",
            self.text,
        )
        self.assertIn("lastBotReply = reply;", self.text)

    def test_replay_uses_checkbox_without_new_fetch(self) -> None:
        handler = self.text.split("replayLast?.addEventListener", 1)[1]
        self.assertIn("add('bot-replay', lastBotReply, renderHTML?.checked === true);", handler)
        self.assertNotIn("fetch(", handler.split("});", 1)[0])

    def test_render_controls_are_absent_outside_llm05(self) -> None:
        environment = Environment(loader=FileSystemLoader(str(TEMPLATE.parent)))
        template = environment.get_template(TEMPLATE.name)
        base = {
            "scenario_title": "test",
            "scenario_intro": "test",
            "warning": "test",
        }
        llm01 = template.render(scenario_id="day1", **base)
        llm05 = template.render(scenario_id="day3", **base)
        self.assertNotIn('id="render-html"', llm01)
        self.assertNotIn('id="replay-last"', llm01)
        self.assertIn('id="render-html"', llm05)
        self.assertIn('id="replay-last"', llm05)


if __name__ == "__main__":
    unittest.main()
