"""Shared visual system and preserved browser-function contracts."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RAG_UI = ROOT / "docker/vuln-rag/app/templates/index.html"
AGENT_UI = ROOT / "docker/vuln-agent/app/templates/index.html"
CONTROL_UI = ROOT / "llm-security-control-plane/application-gateway/index.html"
PRESIDIO_API = ROOT / "examples/day6/presidio/server.py"
NEMO_API = ROOT / "examples/day6/nemo-guardrails/server.py"
RAG_SCENARIOS = ROOT / "docker/vuln-rag/app/scenarios"


class UiDesignSystemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rag = RAG_UI.read_text(encoding="utf-8")
        cls.agent = AGENT_UI.read_text(encoding="utf-8")
        cls.control = CONTROL_UI.read_text(encoding="utf-8")

    def test_three_apps_share_brand_theme_and_core_tokens(self) -> None:
        for source in (self.rag, self.agent):
            self.assertIn("클씨랩", source)
            self.assertIn("AI Security Lab", source)
        self.assertIn("Cloud Security", self.control)
        self.assertIn("LLM Lab", self.control)
        for source in (self.rag, self.agent, self.control):
            self.assertIn('id="theme-toggle"', source)
            self.assertIn("llm-lab-theme", source)
            for token in ("--canvas:#071018", "--signal:#55c2d8", "--incident:#ff6978"):
                self.assertIn(token, source)
            self.assertIn("prefers-reduced-motion:reduce", source)
            self.assertIn("@media", source)

    def test_agent_ui_preserves_execution_workbench_controls(self) -> None:
        for control_id in (
            "portal-home",
            "theme-toggle",
            "split-grid",
            "chat",
            "form",
            "message",
            "send",
            "splitter",
            "trace",
        ):
            self.assertIn(f'id="{control_id}"', self.agent)
        self.assertIn("/api/chat", self.agent)
        self.assertIn("llm06-farmer1-demo-token", self.agent)
        self.assertIn("SERVER AUTHORIZATION DISABLED", self.agent)

    def test_apps_constrain_panels_inside_mobile_viewport(self) -> None:
        self.assertIn(".panel { min-width:0;", self.control)
        self.assertIn(".stack,.panel { min-width:0; }", self.rag)

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
            "guard-panel",
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

    def test_optional_panels_only_activate_when_backing_data_exists(self) -> None:
        self.assertIn('id="guard-panel" class="panel" hidden', self.rag)
        self.assertIn("guardPanel.hidden = true", self.rag)
        self.assertIn("showGuardrailPanel(data.guard_engine, data.guard_mode)", self.rag)
        self.assertIn('scenarioSelect.value !== \'day2\'', self.rag)
        self.assertIn('{% if scenario_id != "day2" %} hidden{% endif %}', self.rag)

    def test_first_party_apps_share_a_responsive_llm_navigation_rail(self) -> None:
        for source in (self.rag, self.agent):
            self.assertIn('id="lab-navigation"', source)
            self.assertIn('aria-label="LLM 실습 이동"', source)
            self.assertIn(".app-layout", source)
            self.assertIn("@media(max-width:760px)", source.replace(" ", ""))
            for llm_number in (1, 2, 5, 6, 7, 8, 9, 10):
                self.assertIn(f">{llm_number:02d}<", source)
            for llm_number in (3, 4):
                self.assertNotIn(f">{llm_number:02d}<", source)
            self.assertIn("LLMGoat", source)
            self.assertIn("DVLA", source)

    def test_app_content_is_top_aligned_and_header_copy_sits_below_title(self) -> None:
        for source in (self.rag, self.agent):
            compact = source.replace(" ", "")
            self.assertIn(".shell{", compact)
            self.assertIn("align-self:start", compact)
            self.assertIn("grid-template-columns:minmax(0,1fr)auto", compact)
            self.assertIn(".mission{grid-column:1/-1;grid-row:2", compact)
            self.assertIn(".top-actions{grid-column:2;grid-row:1", compact)

    def test_html_render_controls_are_server_rendered_only_for_llm05(self) -> None:
        self.assertIn(
            '{% if scenario_id == "day3" %}<label class="render-toggle">',
            self.rag,
        )
        self.assertIn("renderHTML?.checked === true", self.rag)

    def test_vulnerable_rag_ui_hides_internal_day_identifiers(self) -> None:
        for visible_fragment in (
            "LLM Lab {{ scenario_id }}",
            "Active exercise / {{ scenario_id }}",
            "{{ s.id }} — {{ s.title }}",
            "LIVE / {{ scenario_id }}",
            "Day 2 routing",
            "${data.llm_ids.join(' · ')} / ${data.scenario}",
        ):
            with self.subTest(visible_fragment=visible_fragment):
                self.assertNotIn(visible_fragment, self.rag)

        self.assertIn('id="scenario" type="hidden" value="{{ scenario_id }}"', self.rag)
        self.assertNotIn('<select id="scenario"', self.rag)

    def test_api_documentation_titles_use_component_names(self) -> None:
        self.assertIn(
            'FastAPI(title="Microsoft Presidio integration API")',
            PRESIDIO_API.read_text(encoding="utf-8"),
        )
        self.assertIn(
            'FastAPI(title="NeMo Guardrails integration API")',
            NEMO_API.read_text(encoding="utf-8"),
        )

    def test_scenario_titles_use_llm_names_instead_of_day_labels(self) -> None:
        for path in sorted(RAG_SCENARIOS.glob("day[1-5].py")):
            title_lines = [
                line.strip()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip().startswith("title=")
            ]
            with self.subTest(path=path.name):
                self.assertTrue(title_lines)
                self.assertTrue(all("Day " not in line for line in title_lines))

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

    def test_control_center_links_request_evidence_to_observability(self) -> None:
        for control_id in ("grafana-link", "monitor-link", "tempo-link"):
            self.assertIn(f'id="{control_id}"', self.control)
        self.assertIn("/api/traces/${traceId}", self.control)
        self.assertIn("renderInvestigationLinks(d)", self.control)


if __name__ == "__main__":
    unittest.main()
