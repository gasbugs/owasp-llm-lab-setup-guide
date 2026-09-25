import copy
import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'e2e/p20_deployment.py'
spec = importlib.util.spec_from_file_location('p20_deployment', SOURCE)
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)


class DeploymentTests(unittest.TestCase):
    def source(self):
        return {'services': {name: {'container_name': 'old-' + alias, 'read_only': True,
                    'cap_drop': ['ALL'], 'tmpfs': ['/tmp'], 'networks': {'guided': {}},
                    'ports': [{'published': '23002', 'target': 3000}],
                    'volumes': [{'type': 'volume', 'source': 'guided-h20-' + alias, 'target': '/state'}]}
                    for name, alias in deployment.NAMES.items()}}

    def test_only_namespace_and_ports_change(self):
        source = self.source()
        before = copy.deepcopy(source)
        target = deployment.isolate(source, 'guided-p20-check-0123456789', Path('/tmp/test'))
        self.assertEqual(source, before)
        for name, service in target['services'].items():
            self.assertNotIn('ports', service)
            self.assertNotIn('container_name', service)
            self.assertTrue(service['read_only'])
            self.assertEqual(service['cap_drop'], ['ALL'])
            self.assertEqual(service['tmpfs'], ['/tmp'])
            self.assertTrue(service['volumes'][0]['source'].startswith('guided-h20-'))
        self.assertTrue(all(value == {} for value in target['volumes'].values()))
        self.assertNotIn('secrets', target)

    def test_non_publisher_project_rejected(self):
        with self.assertRaises(ValueError): deployment.isolate(self.source(), 'llm-security-guided-course', '/tmp/test')

    def test_other_activity_volume_rejected(self):
        source = self.source()
        source['services']['guided-h20-alerts']['volumes'][0]['source'] = 'guided-h17-state'
        with self.assertRaises(ValueError): deployment.isolate(source, 'guided-p20-check-0123456789', '/tmp/test')

    def test_writable_host_mount_rejected(self):
        source = self.source()
        source['services']['guided-h20-alerts']['volumes'] = [{'type': 'bind', 'source': '/user/state', 'target': '/state'}]
        with self.assertRaises(ValueError): deployment.isolate(source, 'guided-p20-check-0123456789', '/tmp/test')

    def test_external_secret_rejected(self):
        source = self.source()
        source['services']['guided-h20-alertmanager']['secrets'] = ['user-secret']
        with self.assertRaises(ValueError): deployment.isolate(source, 'guided-p20-check-0123456789', '/tmp/test')


if __name__ == '__main__':
    unittest.main()
