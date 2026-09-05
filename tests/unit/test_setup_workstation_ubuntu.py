import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "infrastructure/scripts/student/setup-workstation-ubuntu.sh"


class SetupWorkstationUbuntuDockerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = INSTALLER.read_text(encoding="utf-8")

    def test_existing_docker_is_checked_before_installers(self):
        ready_check = self.script.index("if docker_cli_ready; then")
        official_call = self.script.index(
            "if install_docker_from_official_repository && docker_cli_ready; then"
        )
        ubuntu_call = self.script.index(
            "elif install_docker_from_ubuntu_repository && docker_cli_ready; then"
        )

        self.assertLess(ready_check, official_call)
        self.assertLess(official_call, ubuntu_call)

    def test_official_download_and_apt_operations_are_bounded(self):
        self.assertIn('echo "Docker 공식 저장소 설치를 최대 60초', self.script)
        self.assertIn("--connect-timeout 5 --max-time 15 --retry 1", self.script)
        self.assertIn("remaining_seconds=$((60 - $(date +%s) + official_started))", self.script)
        self.assertIn("sudo timeout 300s apt-get", self.script)
        self.assertIn("sudo timeout 60s systemctl enable --now docker", self.script)

    def test_ubuntu_fallback_installs_engine_and_compose_v2(self):
        fallback_start = self.script.index("install_docker_from_ubuntu_repository()")
        fallback_end = self.script.index("if ! command -v curl", fallback_start)
        fallback = self.script[fallback_start:fallback_end]

        self.assertIn("docker.io docker-compose-v2", fallback)
        self.assertIn("/etc/apt/sources.list.d/docker.list", fallback)
        self.assertIn("Acquire::ForceIPv4=true", fallback)
        self.assertIn("https://mirror.kakao.com/ubuntu", fallback)
        self.assertIn("/etc/apt/sources.list.d/ubuntu.sources", fallback)
        self.assertIn("sudo timeout 60s apt-get", fallback)


if __name__ == "__main__":
    unittest.main()
