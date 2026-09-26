import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from tools.practice_preflight import observations


class PreflightTests(unittest.TestCase):
    def test_observes_without_starting_or_claiming_capacity(self):
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            if command[0] == 'ss':
                return 'tcp LISTEN 0 128 127.0.0.1:28097 0.0.0.0:*\n'
            if 'info' in command:
                return json.dumps({'MemTotal': 1024, 'DockerRootDir': '/not-mounted'})
            return '2.39.4'
        doc = {'services': {'web': {'ports': [{'published': '28097'}]}, 'other': {'ports': [{'published': '28098'}]}}}
        with tempfile.TemporaryDirectory() as root:
            result = observations(Path(root), doc, run)
        self.assertEqual([p['state'] for p in result['ports']], ['in_use', 'not_observed'])
        self.assertIsNone(result['docker_data_free_bytes'])
        self.assertEqual(result['docker_memory_bytes'], 1024)
        self.assertTrue(all('up' not in call and 'stop' not in call for call in calls))

    def test_unavailable_is_not_reported_as_empty(self):
        def unavailable(*args, **kwargs):
            raise subprocess.TimeoutExpired('read-only', 10)
        with tempfile.TemporaryDirectory() as root:
            result = observations(Path(root), {'services': {'web': {'ports': [{'published': '12345'}]}}}, unavailable)
        self.assertFalse(result['docker_available'])
        self.assertEqual(result['ports'][0]['state'], 'unknown')


if __name__ == '__main__':
    unittest.main()
