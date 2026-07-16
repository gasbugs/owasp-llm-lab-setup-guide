"""Fail-closed contracts for repeat Capstone starter uploads."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
UPLOAD = ROOT / "infrastructure/scripts/student/upload-capstone.sh"
INSTALLER = ROOT / "infrastructure/scripts/student/install-capstone-archive.sh"


class CapstoneUploadSafetyTest(unittest.TestCase):
    def test_upload_defaults_to_create_and_never_removes_destination(self) -> None:
        source = UPLOAD.read_text(encoding="utf-8")
        self.assertIn(': "${CAPSTONE_UPLOAD_MODE:=create}"', source)
        self.assertIn("create|backup-replace", source)
        self.assertIn("install-capstone-archive.sh", source)
        self.assertNotIn("rm -rf '$DEST_DIR'", source)
        self.assertNotIn('rm -rf "$DEST_DIR"', source)

    def test_remote_installer_checks_existing_destination_before_extract(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        existing_gate = 'if [ "$mode" = create ] && [ -e "$destination" ]; then'
        self.assertIn(existing_gate, source)
        self.assertLess(source.index(existing_gate), source.index("tar -xzf"))
        self.assertIn("existing learner edits were preserved", source)
        self.assertIn("/home/ubuntu/work/capstone-backups", source)
        self.assertIn('mv "$destination" "$backup_path"', source)
        self.assertNotIn('rm -rf "$destination"', source)

    def test_remote_installer_rejects_destination_outside_learner_work(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".tgz") as archive:
            result = subprocess.run(
                [
                    "bash",
                    str(INSTALLER),
                    archive.name,
                    "/tmp/not-learner-work",
                    "create",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("one direct child", result.stderr)


if __name__ == "__main__":
    unittest.main()
