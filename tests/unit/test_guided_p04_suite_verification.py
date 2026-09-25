"""Authenticated collection and grading of synthetic full-suite records."""
from copy import deepcopy
import sys
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient
import httpx

import test_guided_p04_suite_results as suites

with patch.dict(sys.modules, {"p04_results": suites.binding.results, "p04_suite_results": suites.suite_module}):
    collector = suites.binding.load("p04_suite_verification")
grading = suites.binding.load("p04_grading_api")


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = suites.SuiteTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.requests, self.counts = [], {}
        self.fault = None
        self.verification = collector.SuiteVerification(suites.binding.flow.worker.LAB,
            "http://runner", "http://gateway", "r" * 32, "g" * 32, transport=httpx.MockTransport(self.handle))

    def handle(self, request):
        self.requests.append(request)
        self.assertEqual(request.method, "GET")
        expected = "r" if request.url.host == "runner" else "g"
        self.assertEqual(request.headers["Authorization"], "Bearer " + expected * 32)
        path = request.url.path
        self.counts[path] = self.counts.get(path, 0) + 1
        f = self.fixture
        if path == "/v1/build-info":
            value = f.build
        elif path == "/v1/receipts/" + f.suite:
            value = f.root
        elif path == "/v1/p04/suites/" + f.suite:
            value = f.registration
        elif path == "/v1/p04/suites/" + f.suite + "/resources":
            value = {"suite_id": f.suite, "scope": "registered-resource-state", "observed_at": 1002,
                     "resources": f.resources}
            if f.resources['provider_mode'] == 'aws':
                value['aws_policy_audit'] = {'scope': 'aws-policy-audit',
                    'started_at': 1002, 'observed_at': 1002, 'resources': f.resources,
                    'aws_request_ids': [uuid4().hex for _ in range(3)]}
        else:
            value = next((record for record in f.records if path == "/v1/p04/executions/" + record["execution_id"]), None)
            if value is None:
                return httpx.Response(404)
        value = deepcopy(value)
        if self.fault:
            changed = self.fault(request, value, self.counts[path])
            if changed is not None:
                return changed
        return httpx.Response(200, json=value)

    def collect(self):
        with patch.object(collector.time, "time", return_value=1002):
            return self.verification.collect(self.fixture.suite)

    def test_complete_get_only_collection_refetches_every_record_and_root(self):
        result = self.collect()
        self.assertTrue(result["suite_contract_verified"])
        self.assertEqual(result["provider_mode"], "contract")
        self.assertEqual(result["provider_evidence"], self.fixture.records)
        self.assertEqual(len(self.requests), 62)
        self.assertTrue(all(value == 2 for value in self.counts.values()))

    def test_aws_shaped_collection_requires_fresh_audits_and_requeries_all_executions(self):
        self.fixture = suites.SuiteTests()
        self.fixture.setUp(provider_mode='aws')
        self.addCleanup(self.fixture.doCleanups)
        result = self.collect()
        self.assertTrue(result['suite_contract_verified'])
        self.assertEqual(len(self.requests), 62)
        self.assertTrue(all(count == 2 for count in self.counts.values()))
        before = result['resource_evidence']['before']['aws_policy_audit']
        after = result['resource_evidence']['after']['aws_policy_audit']
        self.assertTrue(set(before['aws_request_ids']).isdisjoint(after['aws_request_ids']))

    def test_aws_shaped_collection_rejects_missing_or_reused_current_audit(self):
        self.fixture = suites.SuiteTests()
        self.fixture.setUp(provider_mode='aws')
        self.addCleanup(self.fixture.doCleanups)
        for mutation in ('missing', 'execution-reuse', 'read-reuse'):
            self.counts.clear()
            seen = []
            def fault(request, value, _count):
                if not request.url.path.endswith('/resources'):
                    return
                proof = value['aws_policy_audit']
                if mutation == 'missing':
                    value.pop('aws_policy_audit')
                elif mutation == 'execution-reuse':
                    proof['aws_request_ids'] = self.fixture.records[0]['policy_audits']['before']['aws_request_ids']
                elif seen:
                    proof['aws_request_ids'] = seen[0]
                else:
                    seen.append(proof['aws_request_ids'])
            self.fault = fault
            with self.subTest(mutation=mutation), self.assertRaises(suites.binding.results.EvidenceError):
                self.collect()

    def test_second_read_changes_to_each_evidence_category_are_rejected(self):
        for target in ("build-info", "receipts", "resources", "executions", "suites"):
            self.requests.clear()
            self.counts.clear()
            def fault(request, value, count):
                if target in request.url.path and count == 2:
                    if target == "resources":
                        value["resources"]["policy_digest"] = "d" * 64
                    else:
                        value["changed"] = True
            self.fault = fault
            with self.subTest(target=target), self.assertRaises(suites.binding.results.EvidenceError):
                self.collect()

    def test_http_missing_redirect_oversize_invalid_json_and_timeout_fail_closed(self):
        for response in (httpx.Response(404), httpx.Response(503),
                         httpx.Response(302, headers={"Location": "http://untrusted"}),
                         httpx.Response(200, content=b" " * 2097153),
                         httpx.Response(200, content=b"not-json")):
            self.requests.clear()
            self.fault = lambda *_: response
            with self.assertRaises(suites.binding.results.EvidenceError):
                self.collect()
            self.assertEqual(len(self.requests), 1)
        def timeout(*_):
            raise httpx.ReadTimeout("private marker")
        self.fault = timeout
        with self.assertRaises(suites.binding.results.EvidenceError) as caught:
            self.collect()
        self.assertNotIn("private marker", str(caught.exception))

    def test_bad_execution_id_is_rejected_before_it_becomes_a_url(self):
        self.fixture.root["cases"][0]["execution_id"] = "../../private"
        with self.assertRaises(suites.binding.results.EvidenceError):
            self.collect()
        self.assertFalse(any("executions" in request.url.path for request in self.requests))

    def test_stale_or_wrong_scope_resource_observation_is_not_a_policy_audit(self):
        for key, value in (("scope", "aws-audit"), ("observed_at", 1), ("observed_at", 1003)):
            self.counts.clear()
            def fault(request, response, _count):
                if request.url.path.endswith("/resources"):
                    response[key] = value
            self.fault = fault
            with self.assertRaises(suites.binding.results.EvidenceError):
                self.collect()

    def test_grading_requires_control_and_suite_only_and_does_not_cache_success(self):
        client = TestClient(grading.create_app(self.verification, control_token="c" * 32))
        self.addCleanup(client.close)
        body = {"suite_id": self.fixture.suite}
        endpoint = "/v1/verify/p04"
        self.assertEqual(client.get("/readyz").status_code, 200)
        self.assertEqual(self.requests, [])
        for token in ("r" * 32, "g" * 32, "wrong"):
            self.assertEqual(client.post(endpoint, json=body, headers={"Authorization": "Bearer " + token}).status_code, 401)
        headers = {"Authorization": "Bearer " + "c" * 32}
        for key in ("security_verdict", "task_completed", "resources", "cases", "source_digest"):
            response = client.post(endpoint, json={**body, key: "private-marker"}, headers=headers)
            self.assertEqual(response.status_code, 422)
            self.assertNotIn("private-marker", response.text)
        self.assertEqual(self.requests, [])
        with patch.object(collector.time, "time", return_value=1002):
            result = client.post(endpoint, json=body, headers=headers).json()
            self.assertTrue(result["task_completed"])
            self.assertEqual(result["security_verdict"], "PASS")
            self.assertEqual(result["provider_mode"], "contract")
            self.fault = lambda *_: httpx.Response(503)
            result = client.post(endpoint, json=body, headers=headers).json()
            self.assertFalse(result["task_completed"])
            self.assertEqual(result["security_verdict"], "ERR")
            self.assertEqual(result["cases"], [])

    def test_simultaneous_grading_is_rejected_and_lock_is_released_after_error(self):
        entered, release = threading.Event(), threading.Event()
        def collect(_suite):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("fixture timeout")
            raise ValueError("private marker")
        self.verification.collect = collect
        client = TestClient(grading.create_app(self.verification, control_token="c" * 32))
        self.addCleanup(client.close)
        options = {"json": {"suite_id": self.fixture.suite}, "headers": {"Authorization": "Bearer " + "c" * 32}}
        replies = []
        thread = threading.Thread(target=lambda: replies.append(client.post("/v1/verify/p04", **options)))
        thread.start()
        try:
            self.assertTrue(entered.wait(3))
            self.assertEqual(client.post("/v1/verify/p04", **options).status_code, 409)
        finally:
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertFalse(replies[0].json()["task_completed"])
        self.assertEqual(client.post("/v1/verify/p04", **options).status_code, 200)

    def test_invalid_origins_and_role_reuse_are_configuration_errors(self):
        for address in ("file:///etc/passwd", "http://user:pass@runner", "http://runner/path", "http://runner?x=1"):
            with self.assertRaises(suites.binding.results.EvidenceError):
                collector.origin(address)
        with self.assertRaises(ValueError):
            grading.create_app(self.verification, control_token=self.verification.app_token)
        with self.assertRaises(suites.binding.results.EvidenceError):
            self.verification.collect("not-a-uuid")
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
