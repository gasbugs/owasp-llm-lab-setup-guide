"""Shared visual system and preserved browser-function contracts."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RAG_UI = ROOT / "docker/vuln-rag/app/templates/index.html"
CONTROL_UI = ROOT / "llm-security-control-plane/application-gateway/index.html"


class UiDesignSystemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rag = RAG_UI.read_text(encoding="utf-8")
        cls.control = CONTROL_UI.read_text(encoding="utf-8")

    def test_two_apps_share_brand_theme_and_core_tokens(self) -> None:
        for source in (self.rag, self.control):
            self.assertIn("Cloud Security", source)
            self.assertIn("LLM Lab", source)
            self.assertIn('id="theme-toggle"', source)
            self.assertIn("llm-lab-theme", source)
            for token in ("--canvas:#071018", "--signal:#55c2d8", "--incident:#ff6978"):
                self.assertIn(token, source)
            self.assertIn("prefers-reduced-motion:reduce", source)
            self.assertIn("@media", source)

    def test_vulnerable_rag_ui_preserves_every_lab_control(self) -> None:
        for control_id in (
            "scenario",
            "lab",
            "llm02-token",
            "chat",
            "message",
            "render-html",
            "replay-last",
            "document-panel",
            "inject-form",
            "refresh-docs",
            "guard-engine",
            "guard-mode",
            "guard-decision",
            "guard-upstream",
            "guard-duration",
            "guard-reason",
            "guard-checks",
        ):
            self.assertIn(f'id="{control_id}"', self.rag)
        for endpoint in (
            "/api/chat",
            "/api/labs/llm08/rag-poisoning/documents",
            "/api/admin/inject-doc",
        ):
            self.assertIn(endpoint, self.rag)
        self.assertIn("renderModelOutputVulnerable", self.rag)
        self.assertIn("renderModelOutputSafe", self.rag)

    def test_control_center_preserves_auth_chat_and_evidence(self) -> None:
        for control_id in (
            "username",
            "password",
            "login",
            "logout",
            "auth-status",
            "classification",
            "purpose",
            "message",
            "send",
            "decision",
            "stages",
            "reply",
            "raw",
        ):
            self.assertIn(f'id="{control_id}"', self.control)
        for endpoint in ("/.well-known/login", "/api/auth/refresh", "/api/auth/logout", "/api/chat"):
            self.assertIn(endpoint, self.control)
        for stage in (
            "presidio_input",
            "nemo_input_rails",
            "bedrock_main",
            "nemo_output_rails",
            "presidio_output",
        ):
            self.assertIn(stage, self.control)


if __name__ == "__main__":
    unittest.main()
