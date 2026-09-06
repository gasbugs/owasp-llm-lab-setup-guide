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

    def test_portal_supports_light_and_dark_themes_without_promotional_copy(self) -> None:
        self.assertIn('id="theme-toggle"', self.source)
        self.assertIn('html[data-theme="light"]', self.source)
        self.assertIn('window.localStorage.setItem("lab-portal-theme"', self.source)
        self.assertNotIn("이름으로 앱을 고르고, 실제 취약 경계를 공격한 뒤", self.source)


if __name__ == "__main__":
    unittest.main()
