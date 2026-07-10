"""Static contract test for replaying one LLM reply through two DOM sinks."""
from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "docker" / "vuln-rag" / "app" / "templates" / "index.html"


class ReplayContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = TEMPLATE.read_text(encoding="utf-8")

    def test_replay_control_exists_and_starts_disabled(self) -> None:
        self.assertIn('id="replay-last" type="button" disabled', self.text)

    def test_last_reply_is_cached_from_api_response(self) -> None:
        self.assertIn("lastBotReply = data.reply;", self.text)

    def test_replay_uses_checkbox_without_new_fetch(self) -> None:
        handler = self.text.split("replayLast.addEventListener", 1)[1]
        self.assertIn("add('bot-replay', lastBotReply, renderHTML.checked);", handler)
        self.assertNotIn("fetch(", handler.split("});", 1)[0])


if __name__ == "__main__":
    unittest.main()
