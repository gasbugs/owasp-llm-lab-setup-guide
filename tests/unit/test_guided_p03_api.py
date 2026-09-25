"""P03 authenticated ASGI boundary with a synthetic backend; no AWS calls."""
import importlib.util
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock
from uuid import uuid4

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway"


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ledger_module, provider_module, api = (load(name) for name in ("p03_ledger", "p03_provider", "p03_api"))


class ApiTests(unittest.TestCase):
    control = {"Authorization": "Bearer control-fixture"}
    verifier = {"Authorization": "Bearer verifier-fixture"}

    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.ledger = ledger_module.SearchLedger(Path(temp.name) / "state.sqlite3")
        self.suite, self.execution = str(uuid4()), str(uuid4())
        self.job = "h03-" + uuid4().hex
        self.backend = Mock()
        self.backend.job_status.return_value = {
            "ingestion_job_id": self.job, "status": "COMPLETE", "provider_mode": "contract"}
        self.backend.retrieve.return_value = {
            "ingestion_job_id": self.job, "source_uris": ["s3://fixture/current.md"],
            "provider_mode": "contract", "provider_request_id": "contract-retrieval"}
        self.resolver = Mock(return_value=self.job)
        self.provider = provider_module.SearchProvider(self.ledger, self.backend)
        self.client = TestClient(api.create_app(
            self.ledger, lambda: self.provider, control_token="control-fixture",
            verifier_token="verifier-fixture", job_resolver=self.resolver))
        self.addCleanup(self.client.close)

    def register(self, **extra):
        return self.client.post("/executions", headers=self.control, json={
            "suite_id": self.suite, "execution_id": self.execution,
            "source_digest": "a" * 64, "runner_digest": "b" * 64, **extra})

    def invoke(self, capability, operation="job_status", **extra):
        return self.client.post("/invoke", headers={"Authorization": "Bearer " + capability}, json={
            "suite_id": self.suite, "execution_id": self.execution,
            "operation": operation, "payload": {}, **extra})

    def test_current_job_is_resolved_on_server_not_supplied_by_caller(self):
        self.assertEqual(self.register(current_job_id="other").status_code, 422)
        self.resolver.assert_not_called()
        response = self.register()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["current_job_id"], self.job)
        self.resolver.assert_called_once_with(self.suite, self.execution)

    def preparation_app(self, **overrides):
        options = {"control_token": "control-fixture", "verifier_token": "verifier-fixture",
                   "job_resolver": self.resolver, "provision_token": "provision-fixture", **overrides}
        client = TestClient(api.create_app(self.ledger, lambda: self.provider, **options))
        self.addCleanup(client.close)
        return client

    def test_preparation_requires_separate_role_and_server_identifier(self):
        preparer = Mock(return_value={"state": "ready"})
        client = self.preparation_app(resource_preparer=preparer)
        body = {"operation_id": self.suite}
        for headers in ({}, self.control, self.verifier):
            self.assertEqual(client.post("/resources/prepare", headers=headers, json=body).status_code, 401)
        preparer.assert_not_called()
        headers = {"Authorization": "Bearer provision-fixture"}
        self.assertEqual(client.post("/resources/prepare", headers=headers, json=body).status_code, 200)
        preparer.assert_called_once_with(self.suite)
        self.assertEqual(client.post("/executions", headers=headers, json={}).status_code, 401)

    def test_preparation_rejects_resource_selection_and_verdicts(self):
        preparer = Mock()
        client = self.preparation_app(resource_preparer=preparer)
        headers = {"Authorization": "Bearer provision-fixture"}
        for extra in ({"account_id": "111111111111"}, {"knowledge_base_id": "foreign"},
                      {"task_completed": True}, {"operation_id": "bad"}):
            self.assertEqual(client.post("/resources/prepare", headers=headers,
                json={"operation_id": self.suite, **extra}).status_code, 422)
        preparer.assert_not_called()

    def test_preparation_reader_is_verifier_only(self):
        reader = Mock(return_value={"state": "error"})
        client = self.preparation_app(preparation_reader=reader)
        for headers in (self.control, {"Authorization": "Bearer provision-fixture"}):
            self.assertEqual(client.get("/preparations/" + self.suite, headers=headers).status_code, 401)
        reader.assert_not_called()
        self.assertEqual(client.get("/preparations/" + self.suite, headers=self.verifier).json(), {"state": "error"})
        reader.assert_called_once_with(self.suite)

    def test_unconfigured_preparation_and_reused_role_rejected(self):
        client = self.preparation_app()
        self.assertEqual(client.post("/resources/prepare", headers={"Authorization": "Bearer provision-fixture"},
                                    json={"operation_id": self.suite}).status_code, 503)
        for token in ("control-fixture", "verifier-fixture", "", "한글"):
            with self.assertRaises(ValueError):
                self.preparation_app(provision_token=token)

    def test_real_provider_adapter_records_status_and_retrieval(self):
        capability = self.register().json()["capability"]
        status = self.invoke(capability)
        result = self.invoke(capability, "retrieve")
        self.assertEqual((status.status_code, result.status_code), (200, 200))
        self.backend.job_status.assert_called_once_with(self.job)
        self.backend.retrieve.assert_called_once_with(self.job)
        self.assertNotIn("provider_request_id", status.json()["response"])
        self.assertEqual(result.json()["response"]["provider_request_id"], "contract-retrieval")
        self.assertNotEqual(status.json()["response"]["observation_id"], result.json()["response"]["observation_id"])
        self.assertEqual(self.client.post(f"/executions/{self.execution}/close", headers=self.control, json={}).status_code, 200)
        receipt = self.client.get(f"/executions/{self.execution}", headers=self.verifier).json()
        self.assertTrue(receipt["closed"])
        self.assertEqual([c["operation"] for c in receipt["calls"]], ["job_status", "retrieve"])
        self.assertNotIn("task_completed", receipt)
        self.assertNotIn("capability_hash", receipt)

    def test_backend_error_records_attempt_and_blocks_later_calls(self):
        capability = self.register().json()["capability"]
        self.backend.job_status.side_effect = RuntimeError("private backend diagnostics")
        response = self.invoke(capability)
        self.assertEqual(response.status_code, 502)
        self.assertNotIn("private", response.text)
        self.assertEqual(self.invoke(capability, "retrieve").status_code, 409)
        self.backend.retrieve.assert_not_called()
        self.assertEqual(self.ledger.read(self.execution)["calls"][0]["state"], "error")

    def test_no_credentials_or_wrong_roles_cannot_mutate_or_read(self):
        self.assertEqual(self.client.post("/executions", json={}).status_code, 401)
        capability = self.register().json()["capability"]
        for token in ("control-fixture", "verifier-fixture", "wrong" * 10):
            self.assertEqual(self.invoke(token).status_code, 401)
        self.assertEqual(self.client.get(f"/executions/{self.execution}", headers=self.control).status_code, 401)
        headers = {"Authorization": "Bearer " + capability}
        self.assertEqual(self.client.post(f"/executions/{self.execution}/close", headers=headers, json={}).status_code, 401)
        self.assertEqual(self.client.get(f"/executions/{self.execution}", headers=headers).status_code, 401)
        self.assertEqual(self.ledger.read(self.execution)["calls"], [])
        self.backend.job_status.assert_not_called()

    def test_caller_cannot_override_job_query_or_verdict(self):
        capability = self.register().json()["capability"]
        for extra in ({"payload": {"job_id": "other"}}, {"payload": {"query": "custom"}},
                      {"task_completed": True}, {"operation": "start_ingestion"}):
            with self.subTest(extra=extra):
                self.assertEqual(self.invoke(capability, **extra).status_code, 422)
        self.assertEqual(self.ledger.read(self.execution)["calls"], [])

    def test_bad_backend_output_never_becomes_complete(self):
        capability = self.register().json()["capability"]
        self.backend.job_status.return_value = {"observation_id": "claimed"}
        self.assertEqual(self.invoke(capability).status_code, 502)
        receipt = self.ledger.read(self.execution)
        self.assertEqual(receipt["calls"][0]["state"], "error")
        self.assertIsNone(receipt["calls"][0]["response"])

    def test_missing_resource_is_not_implicitly_provisioned(self):
        self.resolver.side_effect = ledger_module.LedgerError(409)
        self.assertEqual(self.register().status_code, 409)
        self.backend.assert_not_called()
        self.assertEqual(self.client.get(f"/executions/{self.execution}", headers=self.verifier).status_code, 404)

    def test_verifier_has_no_write_endpoint(self):
        self.register()
        self.assertEqual(self.client.post(f"/executions/{self.execution}/close", headers=self.verifier, json={}).status_code, 401)
        self.assertEqual(self.client.delete(f"/executions/{self.execution}", headers=self.verifier).status_code, 405)
        self.assertFalse(self.ledger.read(self.execution)["closed"])

    def test_unconfigured_suite_preparation_fails_closed(self):
        body = {"suite_id": self.suite, "executions": [{"case_id": "current-complete", "execution_id": self.execution}]}
        self.assertEqual(self.client.post("/suites", headers=self.control, json=body).status_code, 503)
        self.assertEqual(self.client.post("/suites", headers=self.verifier, json=body).status_code, 401)
        self.assertEqual(self.client.post("/suites", json=body).status_code, 401)
        self.backend.assert_not_called()

    def test_suite_preparation_binds_mapping_and_rejects_caller_state(self):
        import hashlib
        import json
        preparer = Mock()
        with TestClient(api.create_app(self.ledger, lambda: self.provider, control_token="control-fixture",
                verifier_token="verifier-fixture", job_resolver=self.resolver, suite_preparer=preparer)) as client:
            rows = [{"case_id": "current-complete", "execution_id": self.execution}]
            body = {"suite_id": self.suite, "executions": rows}
            response = client.post("/suites", headers=self.control, json=body)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["mapping_digest"], hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest())
            self.assertNotIn("task_completed", response.json())
            preparer.assert_called_once_with(self.suite, rows)
            preparer.reset_mock()
            for extra in ({"task_completed": True}, {"current_job_id": "previous"}, {"suite_id": "bad"},
                          {"executions": rows * 2}, {"executions": [{"case_id": "current-complete", "execution_id": "bad"}]}):
                self.assertEqual(client.post("/suites", headers=self.control, json={**body, **extra}).status_code, 422)
            preparer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
