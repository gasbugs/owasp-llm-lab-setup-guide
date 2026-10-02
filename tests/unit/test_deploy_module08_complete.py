"""The retired deployment entrypoint must not mutate local or cloud resources."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RetiredDeploymentTests(unittest.TestCase):
    def test_old_entrypoint_exits_before_any_external_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, PATH=tmp, HOME=tmp)
            result = subprocess.run(
                ["/bin/bash", str(ROOT / "infrastructure/scripts/student/deploy-module08-complete.sh")],
                env=env, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("어떤 자원도 변경하지 않았습니다", result.stderr)
            self.assertIn("docs/GUARDRAILS-SETUP.md", result.stderr)
            self.assertEqual(list(Path(tmp).iterdir()), [])
