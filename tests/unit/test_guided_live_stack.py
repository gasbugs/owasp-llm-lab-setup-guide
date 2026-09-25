"""Guard publisher stack ownership, routing and cleanup order."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('guided_live_stack', ROOT / 'tests/e2e/guided_live_stack.py')
stack_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stack_module)


class LiveStackTests(unittest.TestCase):
    def test_cannot_manage_existing_course_project(self):
        for project in ('llm-security-guided-course', 'guided-p17-check-', '/', ''):
            with self.subTest(project=project), self.assertRaises(ValueError):
                stack_module.LiveStack(ROOT, project, 'H17', 'http://p17:8000')

    @patch.object(stack_module.subprocess, 'check_output', return_value='sha256:test\n')
    @patch.object(stack_module.subprocess, 'run')
    def test_verifier_uses_activity_token_and_internal_listener(self, run, _inspect):
        stack = stack_module.LiveStack(ROOT, 'guided-p17-check-0123456789', 'H17', 'http://p17:8000',
                                      {'H19': 'http://p19:8000'})
        stack.start_verifier('localhost/verifier:test')
        command = run.call_args.args[0]
        self.assertIn('GUIDED_H17_URL=http://p17:8000', command)
        self.assertIn('GUIDED_VERIFIER_H17_TOKEN=publisher-test-verifier', command)
        self.assertIn('GUIDED_H19_URL=http://p19:8000', command)
        self.assertIn('GUIDED_VERIFIER_H19_TOKEN=publisher-test-verifier', command)
        self.assertNotIn('-p', command)
        stack.close()
        self.assertEqual(run.call_args.args[0], ['docker', 'rm', '-f', 'guided-p17-check-0123456789-verifier'])

    @patch.object(stack_module.subprocess, 'check_output', return_value='sha256:test\n')
    @patch.object(stack_module.subprocess, 'run')
    @patch.object(stack_module.socket, 'socket')
    def test_only_proxy_published_and_cleanup_reverses_dependencies(self, socket, run, _inspect):
        socket.return_value.__enter__.return_value.getsockname.return_value = ('127.0.0.1', 28001)
        project = 'guided-p17-check-0123456789'
        stack = stack_module.LiveStack(ROOT, project, 'H17', 'http://p17:8000')
        stack.start_verifier('localhost/verifier:test')
        self.assertEqual(stack.start_browser({'GUIDED_LAB01_URL': 'http://gateway:8000'}), 'http://127.0.0.1:28001')
        launched = [call.args[0] for call in run.call_args_list if call.args[0][:3] == ['docker', 'run', '-d']]
        self.assertEqual(len(launched), 3)
        self.assertEqual([('-p' in command) for command in launched], [False, False, True])
        self.assertIn('127.0.0.1:28001:18097', launched[-1])
        self.assertIn('GUIDED_LAB01_URL=http://gateway:8000', launched[1])
        self.assertNotIn('GUIDED_LAB01_URL=http://gateway:8000', launched[-1])
        stack.close()
        cleanup = [call.args[0] for call in run.call_args_list
                   if call.args[0][1:3] in (['rm', '-f'], ['network', 'rm'])]
        self.assertEqual(cleanup, [
            ['docker', 'rm', '-f', project + '-front-proxy'],
            ['docker', 'rm', '-f', project + '-control-center'],
            ['docker', 'network', 'rm', project + '-browser'],
            ['docker', 'rm', '-f', project + '-verifier']])


if __name__ == '__main__':
    unittest.main()
