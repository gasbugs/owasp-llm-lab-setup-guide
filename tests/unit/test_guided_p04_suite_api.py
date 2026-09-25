"""P04 ASGI suite registration uses real persistent server-owned cases, without AWS."""
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock
from uuid import uuid4

from fastapi.testclient import TestClient

from test_guided_p04_api import CONTROL, VERIFIER, create_app, GuardrailLedger, headers
from test_guided_p04_suites import SuiteStore, case_module


class SuiteAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.resources = {"provider_mode": "contract", "guardrail": {
            "guardrailIdentifier": "p04contract", "guardrailVersion": "DRAFT"},
            "guardrail_arn": None, "policy_digest": "c" * 64}
        self.reader = Mock(side_effect=lambda: deepcopy(self.resources))
        self.store = SuiteStore(self.path, case_module.cases(), self.reader)
        self.ledger = GuardrailLedger(self.path)
        self.factory = Mock(side_effect=AssertionError("provider must not be invoked"))
        self.client = self.make_client(self.store)
        self.suite = str(uuid4())
        self.rows = [{"case_id": row["case_id"], "execution_id": str(uuid4())}
                     for row in case_module.cases()]
        self.request = {"suite_id": self.suite, "cases": self.rows}

    def make_client(self, store):
        return TestClient(create_app(self.ledger, control_token=CONTROL, verifier_token=VERIFIER,
                                     invocation_for=self.factory, suite_store=store))

    def prepare(self):
        return self.client.post("/suites", json=self.request, headers=headers(CONTROL))

    def test_all_cases_resolve_from_registered_store_and_survive_restart(self):
        response = self.prepare()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["prepared"])
        self.assertNotIn("task_completed", response.json())
        self.client = self.make_client(SuiteStore(self.path, case_module.cases(), self.reader))
        for row, case in zip(self.rows, case_module.cases()):
            registration = {"suite_id": self.suite, "execution_id": row["execution_id"],
                            "source_digest": "a" * 64, "runner_digest": "b" * 64}
            result = self.client.post("/executions", json=registration, headers=headers(CONTROL))
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json()["body"], case["body"])
            self.assertEqual(result.json()["guardrail"], self.resources["guardrail"])
        before = self.store.read(self.suite)
        self.reader.reset_mock()
        for _ in range(2):
            result = self.client.get(f"/suites/{self.suite}", headers=headers(VERIFIER))
            self.assertEqual(result.json(), before)
        self.reader.assert_not_called()
        self.factory.assert_not_called()

    def test_roles_cannot_cross_registration_and_evidence_boundaries(self):
        for token in (VERIFIER, "wrong"):
            self.assertEqual(self.client.post("/suites", json=self.request,
                                             headers=headers(token)).status_code, 401)
        self.reader.assert_not_called()
        self.assertEqual(self.prepare().status_code, 200)
        for token in (CONTROL, "wrong"):
            self.assertEqual(self.client.get(f"/suites/{self.suite}",
                                            headers=headers(token)).status_code, 401)

    def test_caller_cannot_submit_cases_policy_or_verdict(self):
        for key in ("body", "guardrail", "security_verdict", "expected", "provider_mode"):
            for nested in (False, True):
                request = deepcopy(self.request)
                target = request["cases"][0] if nested else request
                target[key] = "private-input-marker"
                result = self.client.post("/suites", json=request, headers=headers(CONTROL))
                self.assertEqual(result.status_code, 422)
                self.assertNotIn("private-input-marker", result.text)
        self.reader.assert_not_called()

    def test_missing_reordered_and_duplicate_mappings_are_not_prepared(self):
        duplicate = deepcopy(self.rows)
        duplicate[-1]["execution_id"] = duplicate[0]["execution_id"]
        for rows in (self.rows[:-1], list(reversed(self.rows)), duplicate):
            result = self.client.post("/suites", json={"suite_id": self.suite, "cases": rows},
                                      headers=headers(CONTROL))
            self.assertEqual(result.status_code, 422)
        self.reader.assert_not_called()

    def test_failed_preparation_is_readable_but_never_retried_or_resolved(self):
        self.reader.side_effect = RuntimeError("private-state-marker")
        result = self.prepare()
        self.assertEqual(result.status_code, 409)
        self.assertNotIn("private-state-marker", result.text)
        result = self.client.get(f"/suites/{self.suite}", headers=headers(VERIFIER))
        self.assertEqual(result.json()["state"], "error")
        self.assertEqual(self.prepare().status_code, 409)
        self.assertEqual(self.reader.call_count, 1)
        registration = {"suite_id": self.suite, "execution_id": self.rows[0]["execution_id"],
                        "source_digest": "a" * 64, "runner_digest": "b" * 64}
        self.assertEqual(self.client.post("/executions", json=registration,
                                         headers=headers(CONTROL)).status_code, 409)

    def test_duplicate_registration_preserves_original_mapping(self):
        self.assertEqual(self.prepare().status_code, 200)
        before = self.store.read(self.suite)
        self.assertEqual(self.prepare().status_code, 409)
        self.assertEqual(self.store.read(self.suite), before)
        self.assertEqual(self.reader.call_count, 1)

    def test_health_and_missing_suite_never_read_resources(self):
        self.assertEqual(self.client.get("/readyz").status_code, 200)
        self.assertEqual(self.client.get(f"/suites/{self.suite}",
                                         headers=headers(VERIFIER)).status_code, 404)
        self.reader.assert_not_called()

    def test_suite_store_cannot_be_paired_with_a_different_resolver(self):
        with self.assertRaises(ValueError):
            create_app(self.ledger, control_token=CONTROL, verifier_token=VERIFIER,
                       invocation_for=self.factory, suite_store=self.store, resolve_execution=Mock())

    def test_unconfigured_suite_endpoints_fail_closed(self):
        client = TestClient(create_app(self.ledger, control_token=CONTROL, verifier_token=VERIFIER,
                                      invocation_for=self.factory, resolve_execution=Mock()))
        self.assertEqual(client.post("/suites", json=self.request,
                                     headers=headers(CONTROL)).status_code, 503)
        self.assertEqual(client.get(f"/suites/{self.suite}",
                                    headers=headers(VERIFIER)).status_code, 503)
        self.reader.assert_not_called()

    def test_resource_inspection_is_read_only_verifier_only_and_not_an_aws_audit(self):
        self.assertEqual(self.prepare().status_code, 200)
        before = self.store.read(self.suite)
        path = f"/suites/{self.suite}/resources"
        self.reader.reset_mock()
        for token in (CONTROL, "wrong"):
            self.assertEqual(self.client.get(path, headers=headers(token)).status_code, 401)
        self.reader.assert_not_called()
        for _ in range(2):
            response = self.client.get(path, headers=headers(VERIFIER))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["scope"], "registered-resource-state")
            self.assertEqual(response.json()["resources"], self.resources)
        self.assertEqual(self.store.read(self.suite), before)
        self.assertEqual(self.reader.call_count, 2)
        self.factory.assert_not_called()

    def test_resource_inspection_rejects_changed_expired_and_failed_state(self):
        self.assertEqual(self.prepare().status_code, 200)
        path = f"/suites/{self.suite}/resources"
        self.resources["policy_digest"] = "d" * 64
        self.assertEqual(self.client.get(path, headers=headers(VERIFIER)).status_code, 409)
        self.resources["policy_digest"] = "c" * 64
        self.store.now = lambda: self.store.read(self.suite)["started_at"] + 900
        self.assertEqual(self.client.get(path, headers=headers(VERIFIER)).status_code, 409)
        self.factory.assert_not_called()

    def test_resource_reader_failure_is_sanitized(self):
        self.assertEqual(self.prepare().status_code, 200)
        self.reader.side_effect = RuntimeError("private-state-marker")
        response = self.client.get(f"/suites/{self.suite}/resources", headers=headers(VERIFIER))
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private-state-marker", response.text)


if __name__ == "__main__":
    unittest.main()
