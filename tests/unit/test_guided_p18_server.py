"""The P18 runner must never execute retired shared activity fixtures."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry, Counter


class P18ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-labs/observability/server.py'
        spec = importlib.util.spec_from_file_location('p18_server_test', path)
        cls.server = importlib.util.module_from_spec(spec)
        registry = CollectorRegistry()
        with patch.dict(os.environ, {
            'GUIDED_CONTROL_OBSERVABILITY_TOKEN': 'test-control',
            'GUIDED_VERIFIER_OBSERVABILITY_TOKEN': 'test-verifier',
            'OTEL_EXPORTER_OTLP_ENDPOINT': 'http://127.0.0.1:1',
            'GUIDED_OBSERVABILITY_ACTIVITIES': 'H17,H18,H19,H20',
        }), patch('prometheus_client.Counter', side_effect=lambda *a, **kw: Counter(*a, registry=registry, **kw)):
            spec.loader.exec_module(cls.server)
        cls.client = TestClient(cls.server.app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        cls.server.tp.shutdown()
        cls.server.lp.shutdown()

    def test_retired_execution_cannot_be_enabled_by_environment(self):
        for activity in ('H17', 'H19', 'H20'):
            with self.subTest(activity=activity):
                response = self.client.post('/v1/run/' + activity, json={},
                    headers={'Authorization': 'Bearer test-control'})
                self.assertEqual(response.status_code, 404)

    def test_retired_receipts_are_not_reclassified(self):
        response = self.client.get('/v1/receipts/H20/old-suite',
            headers={'Authorization': 'Bearer test-verifier'})
        self.assertEqual(response.status_code, 404)

    def test_ready_and_authentication_remain(self):
        self.assertEqual(self.client.get('/readyz').status_code, 200)
        self.assertEqual(self.client.post('/v1/run/H18', json={}).status_code, 401)
        self.assertEqual(self.server.ACTIVITIES, {'H18'})
        self.assertFalse(hasattr(self.server, 'H20_ACTIVE'))


if __name__ == '__main__':
    unittest.main()
