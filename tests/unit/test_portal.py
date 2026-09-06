from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
PORTAL = ROOT / "infrastructure/portal/index.html"


class PortalIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PORTAL.read_text(encoding="utf-8")

    def test_cards_use_application_names_instead_of_day_labels(self) -> None:
        for name in (
            "번역기 봇",
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
        for port in (5000, 8000, 8001, 8002, 8010, 8011, 8012, 8013, 8501, 11434):
            with self.subTest(port=port):
                self.assertIn(f"port: {port}", self.source)

    def test_primary_actions_name_the_actual_destination(self) -> None:
        for service_id, port, label in (
            ("prompt-rag", 8000, "번역기 열기"),
            ("data-rag", 8010, "은행 앱 열기"),
            ("output-rag", 8011, "노트북 열기"),
            ("knowledge-rag", 8012, "챗봇 열기"),
            ("resource-rag", 8013, "헬프데스크 열기"),
            ("vuln-agent", 8001, "에이전트 열기"),
            ("llmgoat", 5000, "문제 열기"),
            ("dvla", 8501, "에이전트 열기"),
            ("fake-registry", 8002, "레지스트리 보기"),
            ("ollama", 11434, "모델 목록 보기"),
        ):
            with self.subTest(service_id=service_id):
                self.assertRegex(
                    self.source,
                    rf'id: "{service_id}".*port: {port}.*openLabel: "{label}"',
                )
        self.assertIn("${service.openLabel}</a>", self.source)
        self.assertNotIn(">앱 열기</a>", self.source)

    def test_portal_supports_light_and_dark_themes_without_promotional_copy(self) -> None:
        self.assertIn('id="theme-toggle"', self.source)
        self.assertIn('html[data-theme="light"]', self.source)
        self.assertIn('window.localStorage.setItem("lab-portal-theme"', self.source)
        self.assertNotIn("이름으로 앱을 고르고, 실제 취약 경계를 공격한 뒤", self.source)

    def test_card_grid_has_no_false_timeline_decoration(self) -> None:
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
        self.assertIn('command: ["python", "/app/server.py"]', compose)
        self.assertIn('infrastructure/portal/server.py"', installer)


if __name__ == "__main__":
    unittest.main()
