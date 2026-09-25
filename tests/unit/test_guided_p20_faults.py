"""Keep publisher fault mutations confined to the selected product setting."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('p20_faults', ROOT / 'tests/e2e/p20_faults.py')
faults = importlib.util.module_from_spec(spec)
spec.loader.exec_module(faults)


class P20FaultTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        source = ROOT / 'llm-security-control-plane/guided-labs/h20-alert-dashboard'
        for name in ('dashboard.json', 'alertmanager.yaml'):
            shutil.copy2(source / name, self.directory / name)
        shutil.copy2(ROOT / 'tests/e2e/fixtures/p20/rules.yaml', self.directory / 'rules.yaml')

    def test_each_fault_changes_only_its_setting(self):
        originals = {path.name: path.read_bytes() for path in self.directory.iterdir()}
        for name in faults.FAULTS:
            with self.subTest(fault=name):
                for path, content in originals.items():
                    (self.directory / path).write_bytes(content)
                faults.apply_fault(self.directory, name)
                changed = {path for path, content in originals.items()
                           if (self.directory / path).read_bytes() != content}
                expected = {'constant-panel': 'dashboard.json',
                            'notification-loss': 'alertmanager.yaml'}.get(name, 'rules.yaml')
                self.assertEqual(changed, {expected})
                if name == 'constant-panel':
                    dashboard = json.loads((self.directory / expected).read_text())
                    self.assertEqual(dashboard['panels'][0]['targets'][0]['expr'], 'vector(0)')

    def test_unknown_fault_rejected_without_write(self):
        before = {path.name: path.read_bytes() for path in self.directory.iterdir()}
        with self.assertRaises(ValueError):
            faults.apply_fault(self.directory, 'unknown')
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.directory.iterdir()})

    def test_changed_reference_fails_instead_of_silent_noop(self):
        (self.directory / 'rules.yaml').write_text('groups: []')
        with self.assertRaises(ValueError):
            faults.apply_fault(self.directory, 'always-on')


if __name__ == '__main__':
    unittest.main()
