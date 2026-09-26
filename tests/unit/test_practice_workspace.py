import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('practice_workspace', ROOT / 'tools/practice_workspace.py')
workspace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workspace)


class PracticeWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.relative = workspace.files('P01')[1][0][0]
        self.source = self.root / self.relative
        self.source.parent.mkdir(parents=True)
        self.source.write_text('learner version one\n')

    def test_backup_and_restore_never_replace_current_work(self):
        first = workspace.save_copy(self.root, 'P01')
        second = workspace.save_copy(self.root, 'P01')
        self.assertNotEqual(first['backup_id'], second['backup_id'])
        self.source.write_text('learner version two\n')
        restored = workspace.save_copy(self.root, 'P01', restore=first['backup_id'])
        self.assertEqual(self.source.read_text(), 'learner version two\n')
        self.assertEqual((Path(restored['directory']) / self.relative).read_text(), 'learner version one\n')
        self.assertFalse(restored['learner_files_changed'])
        self.assertEqual(len(list(Path(first['directory']).rglob('*.py'))), 1)

    def test_corrupted_or_wrong_problem_backup_is_not_restored(self):
        first = workspace.save_copy(self.root, 'P01')
        (Path(first['directory']) / self.relative).write_text('changed backup')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            workspace.save_copy(self.root, 'P01', restore=first['backup_id'])
        with self.assertRaises(ValueError):
            workspace.save_copy(self.root, 'P01', restore='../source')
        self.assertEqual(self.source.read_text(), 'learner version one\n')

    def test_source_and_backup_symlinks_are_refused(self):
        self.source.unlink()
        self.source.symlink_to(ROOT / 'README.md')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            workspace.save_copy(self.root, 'P01')
        self.source.unlink()
        self.source.write_text('restored local file')
        state = self.root / workspace.SAVED
        state.parent.mkdir(parents=True)
        state.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            workspace.save_copy(self.root, 'P01')

    def test_same_different_and_unavailable_are_not_grades(self):
        local = workspace.digest(self.source.read_bytes())
        for remote, expected in ((local, 'same'), ('0' * 64, 'different'), (None, 'unavailable')):
            calls = []
            def run(command, **kwargs):
                calls.append(command)
                if 'ps' in command:
                    return 'a' * 64
                if remote is None:
                    raise subprocess.CalledProcessError(1, command)
                return remote + '  /app/learner.py\n'
            result = workspace.running_status(self.root, 'P01', run)
            self.assertEqual(result['files'][0]['state'], expected)
            self.assertTrue(result['not_a_grade'])
            self.assertEqual(calls[-1][0:2], ['docker', 'exec'])
            self.assertNotIn('up', calls[0])

    def test_stopped_container_is_unknown_not_different(self):
        result = workspace.running_status(self.root, 'P01', lambda *a, **kw: '')
        self.assertEqual(result['files'][0]['state'], 'unavailable')
        self.assertIsNone(result['files'][0]['running_sha256'])

    def test_release_checks_exact_revision_without_checkout(self):
        manifest = self.root / 'course.json'
        manifest.write_text(json.dumps({'setup_commit': 'a' * 40}))
        self.assertTrue(workspace.release_status(self.root, manifest, lambda *a, **kw: 'a' * 40)['revision_matches'])
        self.assertFalse(workspace.release_status(self.root, manifest, lambda *a, **kw: 'b' * 40)['revision_matches'])
        manifest.write_text('{"setup_commit":"main"}')
        with self.assertRaises(ValueError):
            workspace.release_status(self.root, manifest)

    def test_inventory_covers_only_22_learner_artifacts(self):
        self.assertEqual(set(workspace.ARTIFACTS), {f'P{i:02}' for i in range(1, 23)})
        compose = (ROOT / 'examples/security-monitoring/compose.guided.yaml').read_text()
        for problem in workspace.ARTIFACTS:
            service, entries = workspace.files(problem)
            self.assertIn('  ' + service + ':', compose)
            for path, target in entries:
                self.assertTrue((ROOT / path).is_file(), path)
                self.assertTrue(target.startswith(('/app/', '/work/')))
                self.assertNotIn('.state', str(path))


if __name__ == '__main__':
    unittest.main()
