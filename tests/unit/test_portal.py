from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
PORTAL = ROOT / "infrastructure/portal/index.html"


class PortalIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PORTAL.read_text(encoding="utf-8")

    def test_cards_use_application_names_instead_of_day_labels(self) -> None:
        self.assertIn("클씨랩 AI Security Lab", self.source)
        self.assertIn("LLM01–LLM10 실습 인덱스", self.source)
        self.assertNotIn("실습 애플리케이션<span>바로가기", self.source)
        for name in (
            "번역기 봇",
            "RAG 번역기",
            "CloudSecurityLab Bank",
            "회사 노트북",
            "PrivateGPT-Lite",
            "IT 헬프데스크 봇",
            "Goat Farm Helper",
            "Damn Vulnerable LLM Agent",
        ):
            with self.subTest(name=name):
                self.assertIn(f'title: "{name}"', self.source)

        for old_title in (
            "Day 1 Vulnerable RAG",
            "Day 2 Vulnerable RAG",
            "Day 3 Vulnerable RAG",
            "Day 4 Vulnerable RAG",
            "Day 5 Vulnerable RAG",
            "Day 3 Vulnerable Agent",
            "Day 3 DVLA",
        ):
            with self.subTest(old_title=old_title):
                self.assertNotIn(old_title, self.source)

    def test_portal_keeps_all_runtime_ports(self) -> None:
        for port in (5000, 8000, 8001, 8002, 8004, 8010, 8011, 8012, 8013, 8501, 11434):
            with self.subTest(port=port):
                self.assertIn(f"port: {port}", self.source)

    def test_primary_actions_name_the_lab_number_or_destination(self) -> None:
        for key, service_id, port, label in (
            ("llm01", "prompt-rag", 8000, "LLM01 열기"),
            ("llm02", "data-rag", 8010, "LLM02 열기"),
            ("llm03", "fake-registry", 8002, "LLM03 열기"),
            ("llm04", "llm04-rag", 8004, "LLM04 열기"),
            ("llm05", "output-rag", 8011, "LLM05 열기"),
            ("llm06", "vuln-agent", 8001, "LLM06 열기"),
            ("llm07", "knowledge-rag", 8012, "LLM07 열기"),
            ("llm08", "data-rag", 8010, "LLM08 열기"),
            ("llm09", "knowledge-rag", 8012, "LLM09 열기"),
            ("llm10", "resource-rag", 8013, "LLM10 열기"),
            ("llmgoat", "llmgoat", 5000, "문제 열기"),
            ("dvla", "dvla", 8501, "에이전트 열기"),
            ("ollama", "ollama", 11434, "모델 목록 보기"),
        ):
            with self.subTest(key=key):
                self.assertRegex(
                    self.source,
                    rf'key: "{key}", id: "{service_id}".*port: {port}.*openLabel: "{label}"',
                )
        self.assertIn("${service.openLabel} ${externalIcon}</a>", self.source)
        self.assertNotIn(">앱 열기</a>", self.source)

    def test_labs_are_separate_and_sorted_by_llm_number(self) -> None:
        orders = [
            int(value)
            for value in re.findall(
                r'key: "llm\d{2}".*?group: "lab", order: (\d+)', self.source
            )
        ]
        self.assertEqual(orders, list(range(1, 11)))
        self.assertIn('.sort((a, b) => a.order - b.order)', self.source)
        self.assertIn('id="lab-jump"', self.source)

    def test_shared_apps_open_the_selected_lab_without_mixed_copy(self) -> None:
        self.assertIn('proxyUrl("/data-rag/?lab=llm02")', self.source)
        self.assertIn('proxyUrl("/data-rag/?lab=llm08-rag-poisoning")', self.source)
        self.assertIn('proxyUrl("/knowledge-rag/?lab=llm07")', self.source)
        self.assertIn('proxyUrl("/knowledge-rag/?lab=llm09")', self.source)
        self.assertNotIn('route: "LLM07 · LLM08 · LLM09"', self.source)

        llm07 = re.search(r'\{ key: "llm07"[^\n]+', self.source)
        llm09 = re.search(r'\{ key: "llm09"[^\n]+', self.source)
        self.assertIsNotNone(llm07)
        self.assertIsNotNone(llm09)
        self.assertNotIn("LLM08", llm07.group(0))
        self.assertNotIn("LLM08", llm09.group(0))

    def test_duplicate_lab_cards_share_one_runtime_probe(self) -> None:
        self.assertIn(
            "const statusServices = [...new Map(services.map((service) => [service.id, service])).values()]",
            self.source,
        )
        self.assertIn('document.querySelectorAll(`[data-status-for="${service.id}"]`)', self.source)

    def test_support_actions_name_the_actual_destination(self) -> None:
        for service_id, port, label in (
            ("llmgoat", 5000, "문제 열기"),
            ("dvla", 8501, "에이전트 열기"),
            ("ollama", 11434, "모델 목록 보기"),
        ):
            with self.subTest(service_id=service_id):
                self.assertRegex(
                    self.source,
                    rf'id: "{service_id}".*port: {port}.*openLabel: "{label}"',
                )
    def test_browser_actions_use_the_port_80_uri_router(self) -> None:
        for path in (
            "/prompt-rag/",
            "/llm04-rag/",
            "/output-rag/",
            "/resource-rag/",
            "/vuln-agent/",
            "/llmgoat/",
            "/dvla/",
        ):
            with self.subTest(path=path):
                self.assertIn(f'proxyUrl("{path}")', self.source)
        self.assertIn("Lab console · port 80", self.source)
        self.assertIn('directUrl(11434, "/api/tags")', self.source)

    def test_portal_supports_light_and_dark_themes_without_promotional_copy(self) -> None:
        self.assertIn('id="theme-toggle"', self.source)
        self.assertIn('html[data-theme="light"]', self.source)
        self.assertIn('window.localStorage.setItem("lab-portal-theme"', self.source)
        self.assertNotIn("이름으로 앱을 고르고, 실제 취약 경계를 공격한 뒤", self.source)

    def test_default_dark_theme_uses_neutral_black_surfaces(self) -> None:
        for declaration in (
            "--canvas: #0b0b0c",
            "--surface: #151517",
            "--surface-raised: #1c1c1f",
            "--ink: #f2f2f3",
            "--line: #303036",
            "background: var(--canvas)",
        ):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, self.source)
        self.assertNotIn("--canvas: #07131c", self.source)
        self.assertNotIn("radial-gradient(circle at 78% -10%", self.source)
        self.assertIn('<link rel="stylesheet" href="/common/theme.css">', self.source)

    def test_number_rail_encodes_the_real_sequence_without_fake_card_timeline(self) -> None:
        self.assertIn(".card-index", self.source)
        self.assertIn('const mark = service.order ? String(service.order).padStart(2, "0")', self.source)
        self.assertNotIn(".grid::before", self.source)
        self.assertNotIn(".card::before", self.source)
        self.assertNotIn("padding-left: 28px", self.source)

    def test_status_checks_use_same_origin_results_instead_of_opaque_cors(self) -> None:
        self.assertIn('fetch(`/api/status/${service.id}`', self.source)
        self.assertIn("response.ok", self.source)
        self.assertIn('result.online ? "online" : "offline"', self.source)
        self.assertNotIn('mode: "no-cors"', self.source)

        server = (ROOT / "infrastructure/portal/server.py").read_text(encoding="utf-8")
        compose = (ROOT / "infrastructure/compose/compose.yaml").read_text(
            encoding="utf-8"
        )
        installer = (ROOT / "infrastructure/scripts/student/install-lab.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('"prompt-rag": "http://prompt-rag:8000/healthz"', server)
        self.assertIn('"llm04-rag": "http://llm04-rag:8004/healthz"', server)
        self.assertIn(
            "image: ghcr.io/gasbugs/owasp-llm-portal:${COMPOSE_IMAGE_TAG:-latest}",
            compose,
        )
        self.assertNotIn('infrastructure/portal/server.py"', installer)


if __name__ == "__main__":
    unittest.main()
