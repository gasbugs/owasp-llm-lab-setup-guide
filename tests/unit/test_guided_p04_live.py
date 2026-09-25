"""P04 publisher safety checks without Docker, Browser, or AWS calls."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
with patch.object(sys, 'path', [str(ROOT / 'tests/e2e'), *sys.path]):
    import check_guided_p04_live as live


class PublisherTests(unittest.TestCase):
    def test_invalid_markdown_stops_before_build_and_external_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            path, output = Path(directory) / 'lesson.md', Path(directory) / 'proof.json'
            path.write_text('# P04\n## 1. 문제\n', encoding='utf-8')
            with patch.object(sys, 'argv', ['check', '--markdown', str(path), '--output', str(output)]), \
                    patch.object(live, 'build') as build, \
                    patch.object(live.subprocess, 'check_output') as read, \
                    patch.object(live.subprocess, 'run') as run:
                with self.assertRaises(ValueError):
                    live.main()
            build.assert_not_called()
            read.assert_not_called()
            run.assert_not_called()
            self.assertFalse(output.exists())

    def test_markdown_bytes_reach_build_without_executing_document_shell(self):
        original = (live.LAB / 'learner.py').read_bytes()
        source = '# 그대로 전달한다.\nasync def invoke_guarded(body, guardrail, services):\n    pass\n'
        with tempfile.TemporaryDirectory() as directory:
            path, output = Path(directory) / 'lesson.md', Path(directory) / 'proof.json'
            path.write_text("# P04\n## 1. 문제\n## 2. 풀이\n```bash\n"
                "cat > llm-security-control-plane/guided-labs/h04-bedrock-guardrail/learner.py <<'EOF'\n"
                + source + 'EOF\nexit 99\n```\n', encoding='utf-8')
            def inspect(role, recipe, context, project):
                self.assertEqual(role, 'learner')
                self.assertNotEqual(recipe.parent, live.LAB)
                self.assertEqual((recipe.parent / 'learner.py').read_bytes(), source.encode('utf-8'))
                raise RuntimeError('stop before Docker')
            with patch.object(sys, 'argv', ['check', '--markdown', str(path), '--output', str(output)]), \
                    patch.object(live, 'build', side_effect=inspect), \
                    patch.object(live.subprocess, 'check_output', return_value=''), \
                    patch.object(live.subprocess, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'stop before Docker'):
                    live.main()
            run.assert_not_called()
            proof = json.loads(output.read_text())
            self.assertEqual(proof['source_digest'], hashlib.sha256(source.encode('utf-8')).hexdigest())
            self.assertNotIn('checked', proof)
        self.assertEqual((live.LAB / 'learner.py').read_bytes(), original)

    def test_source_bytes_reach_only_temporary_build_and_checkout_stays_unchanged(self):
        original = (live.LAB / 'learner.py').read_bytes()
        source = b'async def invoke_guarded(body, guardrail, services):\n    raise ValueError()\n'
        with tempfile.TemporaryDirectory() as directory:
            path, output = Path(directory) / 'learner.py', Path(directory) / 'proof.json'
            path.write_bytes(source)
            def inspect(role, recipe, context, project):
                self.assertEqual(role, 'learner')
                self.assertNotEqual(recipe.parent, live.LAB)
                self.assertEqual((recipe.parent / 'learner.py').read_bytes(), source)
                self.assertEqual(len(list(recipe.parent.iterdir())), 8)
                raise RuntimeError('stop before Docker')
            with patch.object(sys, 'argv', ['check', '--source', str(path), '--output', str(output)]), \
                    patch.object(live, 'build', side_effect=inspect), \
                    patch.object(live.subprocess, 'check_output', return_value=''), \
                    patch.object(live.subprocess, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'stop before Docker'):
                    live.main()
            run.assert_not_called()
            proof = json.loads(output.read_text())
            self.assertEqual(proof['source_digest'], hashlib.sha256(source).hexdigest())
            self.assertEqual(proof['provider_mode'], 'contract')
            self.assertNotIn('checked', proof)
        self.assertEqual((live.LAB / 'learner.py').read_bytes(), original)

    def test_existing_evidence_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'proof.json'
            output.write_text('keep')
            with patch.object(sys, 'argv', ['check', '--starter', '--output', str(output)]), \
                    patch.object(live, 'build') as build:
                with self.assertRaises(SystemExit):
                    live.main()
            build.assert_not_called()
            self.assertEqual(output.read_text(), 'keep')

    def test_test_role_tokens_are_distinct_and_satisfy_api_length(self):
        self.assertEqual(len(set(live.TOKENS.values())), len(live.TOKENS))
        self.assertTrue(all(value.isascii() and len(value) >= 32 for value in live.TOKENS.values()))

    def test_startup_polling_is_bounded(self):
        with patch.object(live.time, 'monotonic', side_effect=[0, 31]), \
                patch.object(live.time, 'sleep') as sleep:
            with self.assertRaises(TimeoutError):
                live.wait_ready(lambda: 503)
        sleep.assert_not_called()

    def test_aws_requires_explicit_account_credentials_and_browser(self):
        with tempfile.TemporaryDirectory() as directory:
            output = str(Path(directory) / 'proof.json')
            for extra in (['--aws-account', '000000000000'],
                          ['--aws-config-dir', directory],
                          ['--aws-config-dir', directory, '--aws-account', 'bad', '--browser-python', '/python']):
                with self.subTest(extra=extra), patch.object(sys, 'argv', ['check', '--starter', '--output', output, *extra]), \
                        patch.object(live, 'build') as build:
                    with self.assertRaises(SystemExit):
                        live.main()
                    build.assert_not_called()

    def test_cleanup_stops_owned_writers_then_preserves_journal_and_deletes_exact_preparation(self):
        project = 'guided-p04-check-0123456789'
        stack = SimpleNamespace(project=project, images={'gateway': 'g', 'learner': 'l', 'control-center': 'c'})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'preparation.json'
            prepared = {'state': 'ready', 'resources': {'provider_mode': 'aws'}}
            path.write_text(json.dumps({'preparation': prepared}))
            proof = {'aws_preflight': {'resources_absent': True}}
            with patch.object(live.subprocess, 'run') as run, \
                    patch.object(live.subprocess, 'check_output', return_value=b'SQLite format 3\x00fixture'), \
                    patch.object(live, 'aws_call', return_value={'resources_absent': True}) as aws:
                live.cleanup_aws(stack, proof, path, Path(directory) / 'journal.sqlite3')
            self.assertEqual([call.args[0][:3] for call in run.call_args_list[:2]],
                             [['docker', 'stop', project + '-control-center'], ['docker', 'stop', project + '-learner']])
            self.assertEqual((Path(directory) / 'journal.sqlite3').read_bytes(), b'SQLite format 3\x00fixture')
            aws.assert_called_once_with(project, 'cleanup', {'before': proof['aws_preflight'], 'prepared': prepared})
            self.assertTrue(proof['aws_cleanup']['resources_absent'])

    def test_incomplete_preparation_preserves_journal_without_aws_deletion(self):
        stack = SimpleNamespace(project='guided-p04-check-0123456789', images={'gateway': 'g'})
        with tempfile.TemporaryDirectory() as directory, patch.object(live.subprocess, 'run') as run, \
                patch.object(live.subprocess, 'check_output', return_value=b'SQLite format 3\x00fixture'), \
                patch.object(live, 'aws_call') as aws:
            proof = {}
            live.cleanup_aws(stack, proof, Path(directory) / 'missing.json', Path(directory) / 'journal.sqlite3')
            aws.assert_not_called()
            self.assertFalse(proof['aws_cleanup']['performed'])
            self.assertEqual((Path(directory) / 'journal.sqlite3').read_bytes(), b'SQLite format 3\x00fixture')
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
