from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "docker/vuln-agent/app/templates/index.html"


class VulnAgentUILayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = TEMPLATE.read_text(encoding="utf-8")

    def test_splitter_is_accessible_and_resizable(self) -> None:
        self.assertIn('id="splitter"', self.html)
        self.assertIn('role="separator"', self.html)
        self.assertIn('aria-valuemin="25"', self.html)
        self.assertIn('aria-valuemax="75"', self.html)
        self.assertIn("splitter.addEventListener('pointerdown'", self.html)
        self.assertIn("splitter.addEventListener('keydown'", self.html)
        self.assertIn("setPointerCapture", self.html)

    def test_long_trace_cannot_expand_a_grid_column(self) -> None:
        self.assertIn(
            "grid-template-columns: minmax(0, var(--left-pane-width)) 12px minmax(0, 1fr)",
            self.html,
        )
        self.assertIn(".pane { min-width: 0; }", self.html)
        self.assertIn(".trace { white-space: pre-wrap; }", self.html)
        self.assertIn("overflow-wrap: anywhere", self.html)
        self.assertIn("word-break: break-word", self.html)

    def test_mobile_layout_hides_the_desktop_splitter(self) -> None:
        self.assertIn("@media (max-width: 720px)", self.html)
        self.assertIn(".splitter { display: none; }", self.html)


if __name__ == "__main__":
    unittest.main()
