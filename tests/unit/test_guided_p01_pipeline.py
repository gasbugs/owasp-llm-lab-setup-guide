"""Actual P01 ASGI services and persisted evidence; no AWS or socket traffic.

Only inter-service HTTP transport and the learner implementation are substituted.
Receipts, execution records, authentication and grading use production handlers.
This is not a Docker-network, Browser or AWS end-to-end test.
"""

from contextlib import ExitStack
import os
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import httpx
from fastapi.testclient import TestClient

import test_guided_control_center as control_fixture
import test_guided_evidence_verifier as verifier_fixture
import test_guided_p01_gateway as gateway_fixture


class P01PipelineTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ))
        gateway_fixture.P01GatewayTests.setUpClass()
        self.stack.callback(gateway_fixture.P01GatewayTests.tearDownClass)
        verifier_fixture.GuidedEvidenceVerifierTests.setUpClass()
        self.stack.callback(verifier_fixture.GuidedEvidenceVerifierTests.tearDownClass)
        self.gateway = gateway_fixture.P01GatewayTests.server
        self.verifier = verifier_fixture.GuidedEvidenceVerifierTests.server
        self.control = control_fixture.load_server()
        self.stack.enter_context(patch.object(self.control, "LAB_TOKEN", "unit-control"))
        self.stack.enter_context(patch.object(self.control, "VERIFIER_TOKEN", "control-verifier"))
        self.stack.enter_context(patch.object(self.verifier, "LAB_TOKEN", "unit-verifier"))
        gateway = self.stack.enter_context(TestClient(self.gateway.app))
        verifier = self.stack.enter_context(TestClient(self.verifier.app))
        self.client = self.stack.enter_context(TestClient(self.control.app))
        self.client.get("/")
        bootstrap = self.client.get("/api/bootstrap").json()
        self.headers = {"Origin": "http://testserver", "X-CSRF-Token": bootstrap["csrf_token"]}
        self.calls = []
        owner = self

        class RoutedAsyncClient:
            def __init__(self, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def post(self, url, *, json, headers):
                owner.calls.append(url)
                parsed = urlsplit(url)
                if parsed.netloc == urlsplit(owner.control.LAB_URL).netloc:
                    return gateway.post(parsed.path, json=json, headers=headers)
                if parsed.netloc == urlsplit(owner.control.VERIFIER_URL).netloc:
                    return verifier.post(parsed.path, json=json, headers=headers)
                raise AssertionError(f"unexpected destination: {url}")

        def routed_get(url, *, headers, timeout):
            parsed = urlsplit(url)
            self.assertEqual(parsed.netloc, urlsplit(self.verifier.LAB_URL).netloc)
            self.calls.append(url)
            return gateway.get(parsed.path, headers=headers)

        self.stack.enter_context(patch.object(httpx, "AsyncClient", RoutedAsyncClient))
        self.stack.enter_context(patch.object(httpx, "get", routed_get))

    def verify(self, implementation):
        with patch.object(self.gateway.learner, "handle_request", implementation):
            return self.client.post("/api/hands-on/H01/verify", headers=self.headers)

    def test_equivalent_implementations_pass_with_actual_persisted_evidence(self):
        for implementation in (gateway_fixture.valid, gateway_fixture.alternate):
            with self.subTest(implementation=implementation.__name__):
                response = self.verify(implementation)
                self.assertEqual(response.status_code, 200, response.text)
                result = response.json()
                self.assertEqual(result["activity_id"], "P01")
                self.assertEqual(result["security_verdict"], "PASS", result)
                self.assertTrue(result["task_completed"], result)
        with self.gateway.connect() as database:
            self.assertEqual(database.execute("SELECT COUNT(*) FROM executions").fetchone()[0], 42)
            self.assertEqual(database.execute("SELECT COUNT(*) FROM receipts").fetchone()[0], 14)

    def test_deny_all_is_incomplete_and_releases_session(self):
        def deny(body, client):
            raise ValueError("not implemented")
        response = self.verify(deny)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["detail"]["course_verdict"], "ERR")
        self.assertFalse(response.json()["detail"]["task_completed"])
        self.assertEqual(response.json()["detail"]["security_verdict"], "ERR")
        self.assertFalse(self.control.ACTIVE_SESSIONS)
        self.assertTrue(self.verify(gateway_fixture.valid).json()["task_completed"])

    def test_changed_provided_runner_is_incomplete(self):
        for name in ("server.py", "provider.py"):
            with self.subTest(name=name):
                changed = {**self.gateway.runner_digests(), name: "0" * 64}
                with patch.object(self.gateway, "runner_digests", return_value=changed):
                    result = self.verify(gateway_fixture.valid).json()
                self.assertEqual(result["security_verdict"], "ERR", result)
                self.assertFalse(result["task_completed"], result)


    def test_starter_has_no_provider_receipt(self):
        response = self.client.post("/api/hands-on/H01/verify", headers=self.headers)
        self.assertEqual(response.status_code, 502)
        self.assertFalse(response.json()["detail"]["task_completed"])
        with self.gateway.connect() as database:
            self.assertEqual(database.execute("SELECT COUNT(*) FROM receipts").fetchone()[0], 0)

    def test_browser_cannot_submit_completion_or_contract(self):
        response = self.client.post("/api/hands-on/H01/verify", headers=self.headers,
                                    json={"task_completed": True, "security_verdict": "PASS"})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.calls, [])

    def test_preflight_is_not_problem_completion(self):
        with patch.object(self.gateway.learner, "handle_request", gateway_fixture.valid):
            response = self.client.post("/api/provider-preflight", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["security_verdict"], "PASS", result)
        self.assertFalse(result["task_completed"])

    def test_changed_message_is_rejected_by_actual_verifier(self):
        # Keep invalid requests invalid; only change otherwise valid model input.
        def implementation(body, client):
            class ChangedClient:
                def converse(self, **kwargs):
                    kwargs["messages"] = [{"role": "user", "content": [{"text": "constant answer"}]}]
                    return client.converse(**kwargs)
            return gateway_fixture.valid(body, ChangedClient())
        result = self.verify(implementation).json()
        self.assertEqual(result["security_verdict"], "ERR", result)
        self.assertFalse(result["task_completed"])

    def test_verifier_failure_does_not_erase_execution_or_claim_completion(self):
        with patch.object(self.control, "VERIFIER_TOKEN", "wrong-token"):
            response = self.verify(gateway_fixture.valid)
        self.assertEqual(response.status_code, 502)
        detail = response.json()["detail"]
        self.assertEqual(detail["stopped_stage"], "evidence_verifier")
        self.assertFalse(detail["task_completed"])
        self.assertIsNone(detail["downstream_called"])
        with self.gateway.connect() as database:
            self.assertEqual(database.execute("SELECT COUNT(*) FROM receipts").fetchone()[0], 7)

    def test_transport_error_is_explicitly_incomplete(self):
        with patch.object(httpx, "AsyncClient", side_effect=httpx.ConnectError("offline")):
            response = self.verify(gateway_fixture.valid)
        self.assertEqual(response.status_code, 502)
        detail = response.json()["detail"]
        self.assertEqual(detail["stopped_stage"], "internal_transport")
        self.assertFalse(detail["task_completed"])
        self.assertFalse(self.control.ACTIVE_SESSIONS)


if __name__ == "__main__":
    unittest.main()
