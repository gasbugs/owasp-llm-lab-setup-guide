from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/install-guided-practice.sh"
COMPOSE = ROOT / "examples/security-monitoring/compose.guided.yaml"
PRACTICE_MANIFEST = ROOT / "tools/guided-practice-files.tsv"
PRACTICE_INIT = ROOT / "tools/initialize-guided-practice.sh"
PRACTICE_PREPARE = ROOT / "tools/prepare-guided-practice-build.sh"
PRACTICE_APPLY = ROOT / "tools/apply-guided-practice.sh"


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
        install = self.text.index("up -d --build --force-recreate --remove-orphans")
        self.assertLess(prerequisites, preflight)
        self.assertLess(preflight, install)

    def test_install_recreates_stale_images_and_verifies_runtime_ids(self):
        self.assertIn("up -d --build --force-recreate --remove-orphans", self.text)
        self.assertIn("docker image inspect --format '{{.Id}}'", self.text)
        self.assertIn('if [[ "$running_image" != "$current_image" ]]', self.text)
        self.assertIn("최신 로컬 이미지를 사용하지 않는 서비스", self.text)

    def test_practice_work_uses_numbered_home_files_and_shadow_build_context(self):
        rows = [line.split("|") for line in PRACTICE_MANIFEST.read_text().splitlines()
                if line and not line.startswith("#")]
        self.assertEqual(len(rows), 24)
        self.assertEqual(len({row[0] for row in rows}), 23)
        for display_id, source, workspace_name, services in rows:
            with self.subTest(display_id=display_id, workspace_name=workspace_name):
                self.assertTrue(workspace_name.startswith(f"{display_id}_"))
                self.assertTrue((ROOT / "llm-security-control-plane" / source).is_file())
                self.assertTrue(services)

        init = PRACTICE_INIT.read_text()
        prepare = PRACTICE_PREPARE.read_text()
        apply = PRACTICE_APPLY.read_text()
        self.assertIn('$HOME/owasp-llm-practice', init)
        self.assertIn('[[ ! -e "$workspace_file" ]]', init)
        self.assertIn('show "HEAD:llm-security-control-plane/$source_path"', init)
        self.assertIn('archive HEAD llm-security-control-plane', prepare)
        self.assertIn('install -D -m 0644 "$workspace_file" "$BUILD_ROOT/$source_path"', prepare)
        self.assertIn('--file "$override_file" build', apply)
        self.assertNotIn('cp "$workspace_file" "$CONTROL_ROOT/', apply)
        self.assertIn('initialize-guided-practice.sh', self.text)
        self.assertIn('prepare-guided-practice-build.sh', self.text)
        self.assertIn('--file "$PRACTICE_OVERRIDE"', self.text)

    def test_control_center_edits_and_applies_numbered_workspace_files(self):
        html = (ROOT / "llm-security-control-plane/guided-control-center/index.html").read_text()
        rows = [line.split("|") for line in PRACTICE_MANIFEST.read_text().splitlines()
                if line and not line.startswith("#")]
        for display_id, _source, workspace_name, _services in rows:
            with self.subTest(display_id=display_id, workspace_name=workspace_name):
                self.assertIn(f"vi ~/owasp-llm-practice/{workspace_name}", html)
                self.assertIn(f"./tools/apply-guided-practice.sh {display_id}", html)
        self.assertNotIn(
            "vi ~/owasp-llm-lab-setup-guide/llm-security-control-plane/guided-labs/",
            html,
        )


if __name__ == "__main__":
    unittest.main()
