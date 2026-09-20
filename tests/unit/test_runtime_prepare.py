import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'examples/runtime-security/prepare.py'


class RuntimePreparationTests(unittest.TestCase):
    def test_missing_isolated_credentials_does_not_create_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run([sys.executable, str(SCRIPT)], cwd=root,
                                    env={**os.environ, 'HOME': directory}, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / '.state').exists())

    def test_preparation_uses_only_isolated_directory_and_preserves_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            credentials = root / '.config/owasp-runtime-aws'
            credentials.mkdir(parents=True)
            (credentials / 'credentials').write_text('[default]\n')
            (credentials / 'config').write_text('[default]\nregion=us-east-1\n')
            env = {**os.environ, 'HOME': directory, 'AWS_PROFILE': 'provisioner'}
            first = subprocess.run([sys.executable, str(SCRIPT)], cwd=root, env=env,
                                   capture_output=True, text=True, check=True)
            state = root / '.state/runtime.env'
            content = state.read_bytes()
            values = dict(line.split('=', 1) for line in content.decode().splitlines())
            self.assertEqual(values['AWS_PROFILE'], 'default')
            self.assertEqual(values['AWS_CREDENTIALS_DIR'], str(credentials))
            self.assertEqual(state.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(values['TEAM_A_TOKEN'], first.stdout)
            self.assertFalse(json.loads(first.stdout)['secrets_printed'])
            second = subprocess.run([sys.executable, str(SCRIPT)], cwd=root, env=env,
                                    capture_output=True, text=True)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(state.read_bytes(), content)


if __name__ == '__main__':
    unittest.main()
