from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/install-guided-practice.sh"
COMPOSE = ROOT / "examples/security-monitoring/compose.guided.yaml"


class GuidedInstallerTests(unittest.TestCase):
    def setUp(self):
        self.text = SCRIPT.read_text(encoding="utf-8")

    def test_shell_syntax(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

    def test_installer_derives_every_required_secret_from_compose(self):
        required = set(re.findall(r"\$\{(\w+):\?", COMPOSE.read_text(encoding="utf-8")))
        self.assertTrue(required)
        self.assertIn("grep -oE", self.text)
        self.assertIn("sort -u", self.text)
        self.assertIn("openssl rand -hex", self.text)
        self.assertNotIn("rm -", self.text)

    def test_existing_install_requires_y_and_preserves_state(self):
        self.assertIn('if [[ "$installed" == true ]]', self.text)
        self.assertIn("read -r answer", self.text)
        self.assertIn('"$answer" == "y"', self.text)
        self.assertIn("기존 Token과 volume을 보존", self.text)
        self.assertNotIn("down -v", self.text)
        self.assertNotIn("--project-name", self.text)

    def test_prerequisites_precede_compose_install(self):
        prerequisites = self.text.index('log "1/5"')
        preflight = self.text.index("practice_preflight.py")
        install = self.text.index("up -d --build")
        self.assertLess(prerequisites, preflight)
        self.assertLess(preflight, install)


if __name__ == "__main__":
    unittest.main()
