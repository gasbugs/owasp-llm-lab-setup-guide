import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import httpx

SOURCE = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-labs/h20-alert-dashboard/grafana_reader.py'
spec = importlib.util.spec_from_file_location('p20_reader', SOURCE)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


class ReaderTests(unittest.TestCase):
    def run_case(self, *, exists=False, admin=False, role='Viewer', identity_status=200,
                 initial_permission_status=None):
        self.requests = []
        def handle(request):
            self.requests.append(request)
            path = request.url.path
            if path == '/api/dashboards/uid/guided-p20/permissions':
                if len(self.requests) == 1 and initial_permission_status:
                    if initial_permission_status == 'timeout':
                        raise httpx.ReadTimeout('publisher fixture', request=request)
                    return httpx.Response(initial_permission_status, json={})
                return httpx.Response(200, json=[{'role': 'Viewer', 'permission': 1}])
            if path == '/api/users/lookup':
                return httpx.Response(200 if exists else 404, json={})
            if path == '/api/admin/users':
                return httpx.Response(200, json={'id': 2})
            if path == '/api/user':
                return httpx.Response(identity_status, json={'id': 2, 'login': 'p20-reader', 'orgId': 1, 'isGrafanaAdmin': admin})
            if path == '/api/user/orgs':
                return httpx.Response(200, json=[{'orgId': 1, 'role': role}])
            if path == '/api/dashboards/uid/guided-p20':
                return httpx.Response(200, json={'dashboard': {}})
            raise AssertionError(path)
        with httpx.Client(base_url='http://grafana', transport=httpx.MockTransport(handle)) as client:
            return reader.provision(client, 'admin-secret', 'reader-secret')

    def test_create_and_verify_viewer(self):
        self.assertEqual(self.run_case()['role'], 'Viewer')
        self.assertEqual(self.requests[0].url.path, '/api/dashboards/uid/guided-p20/permissions')
        writes = [r for r in self.requests if r.method != 'GET']
        self.assertEqual(len(writes), 1)
        body = json.loads(writes[0].content)
        self.assertEqual(body['login'], 'p20-reader')
        self.assertEqual(body['OrgId'], 1)
        self.assertNotEqual(self.requests[0].headers['authorization'], self.requests[-1].headers['authorization'])

    def test_existing_viewer_is_read_only_no_password_reset(self):
        self.run_case(exists=True)
        self.assertTrue(all(r.method == 'GET' for r in self.requests))

    def test_initial_permission_readiness_retries_without_duplicate_creation(self):
        for status in (404, 502, 503, 504, 'timeout'):
            with self.subTest(status=status), patch.object(reader.time, 'sleep'):
                self.assertEqual(self.run_case(initial_permission_status=status)['role'], 'Viewer')
                self.assertEqual(sum(r.method == 'POST' for r in self.requests), 1)

    def test_permission_auth_failure_is_not_readiness_or_permission_grant(self):
        with self.assertRaises(httpx.HTTPStatusError):
            self.run_case(initial_permission_status=401)
        self.assertEqual(len(self.requests), 1)

    def test_existing_admin_not_accepted_or_mutated(self):
        with self.assertRaises(ValueError): self.run_case(exists=True, admin=True)
        self.assertTrue(all(r.method == 'GET' for r in self.requests))

    def test_editor_not_accepted(self):
        with self.assertRaises(ValueError): self.run_case(exists=True, role='Editor')

    def test_changed_password_does_not_reset_existing_account(self):
        with self.assertRaises(httpx.HTTPStatusError): self.run_case(exists=True, identity_status=401)
        self.assertTrue(all(r.method == 'GET' for r in self.requests))

    def test_credentials_must_be_separate(self):
        for admin, password in [('', 'reader'), ('admin', ''), ('same', 'same')]:
            with self.assertRaises(ValueError): reader.provision(None, admin, password)

    def test_missing_dashboard_permission_stops_before_creating_user(self):
        requests = []
        def handle(request):
            requests.append(request)
            return httpx.Response(200, json=[])
        with httpx.Client(base_url='http://grafana', transport=httpx.MockTransport(handle)) as client:
            with patch.object(reader.time, 'monotonic', side_effect=[0, 61]):
                with self.assertRaises(TimeoutError): reader.provision(client, 'admin-secret', 'reader-secret')
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].method, 'GET')


if __name__ == '__main__':
    unittest.main()
