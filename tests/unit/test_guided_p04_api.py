"""P04 ASGI authentication and persistent lifecycle, with a synthetic backend."""
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock
from uuid import uuid4

from fastapi.testclient import TestClient

GATEWAY = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway"
sys.path.insert(0, str(GATEWAY))
try:
    from p04_api import create_app
    from p04_contract import expected_arguments
    from p04_invocation import Invocation
    from p04_ledger import GuardrailLedger
finally:
    sys.path.remove(str(GATEWAY))

CONTROL, VERIFIER = "control-" * 8, "verifier-" * 8


def headers(token):
    return {"Authorization": "Bearer " + token}


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ledger = GuardrailLedger(Path(self.temp.name) / "state.sqlite3")
        self.suite, self.execution = str(uuid4()), str(uuid4())
        self.body = {"operation": "apply_guardrail", "text": "normal"}
        self.guardrail = {"guardrailIdentifier": "p04fixture", "guardrailVersion": "DRAFT"}
        self.resolve = Mock(return_value={"body": self.body, "guardrail": self.guardrail,
                            "resource_digest": "c" * 64, "provider_mode": "contract"})
        self.backend = Mock(return_value={"action": "NONE", "outputs": []})
        self.invocation = Invocation(self.ledger, self.backend, lambda: "c" * 64)
        self.factory = Mock(return_value=self.invocation)
        self.app = create_app(self.ledger, control_token=CONTROL, verifier_token=VERIFIER,
                              resolve_execution=self.resolve, invocation_for=self.factory)
        self.client = TestClient(self.app)
        self.registration = {"suite_id": self.suite, "execution_id": self.execution,
                             "source_digest": "a" * 64, "runner_digest": "b" * 64}

    def register(self):
        response = self.client.post("/executions", json=self.registration, headers=headers(CONTROL))
        self.assertEqual(response.status_code, 200)
        return response.json()

    def invoke(self, capability, **changes):
        payload = {"suite_id": self.suite, "execution_id": self.execution, "operation": "apply_guardrail",
                   "payload": expected_arguments(self.body, self.guardrail)}
        payload.update(changes)
        return self.client.post("/invoke", json=payload, headers=headers(capability))

    def test_full_lifecycle_uses_server_case_and_read_only_verifier(self):
        grant = self.register()
        self.assertEqual(grant["body"], self.body)
        self.resolve.assert_called_once_with(self.suite, self.execution)
        response = self.invoke(grant["capability"])
        self.assertEqual(response.status_code, 200)
        closed = self.client.post(f"/executions/{self.execution}/close", json={}, headers=headers(CONTROL))
        self.assertEqual(closed.status_code, 200)
        before = self.ledger.read(self.execution)
        for _ in range(2):
            result = self.client.get(f"/executions/{self.execution}", headers=headers(VERIFIER))
            self.assertEqual(result.json(), before)
        self.assertEqual(self.ledger.read(self.execution), before)
        self.assertEqual(self.backend.call_count, 1)
        self.assertNotIn(grant["capability"], result.text)
        self.assertTrue(result.json()["closed"])
        self.assertNotIn("task_completed", result.json())

    def test_wrong_roles_cannot_register_close_or_read(self):
        grant = self.register()
        for token in (VERIFIER, grant["capability"], "wrong"):
            self.assertEqual(self.client.post("/executions", json=self.registration,
                headers=headers(token)).status_code, 401)
            self.assertEqual(self.client.post(f"/executions/{self.execution}/close", json={},
                headers=headers(token)).status_code, 401)
        for token in (CONTROL, grant["capability"], "wrong"):
            self.assertEqual(self.client.get(f"/executions/{self.execution}",
                headers=headers(token)).status_code, 401)
        self.backend.assert_not_called()

    def test_lifecycle_tokens_cannot_invoke_provider(self):
        self.register()
        for token in (CONTROL, VERIFIER, "wrong-" * 10):
            self.assertEqual(self.invoke(token).status_code, 401)
        self.factory.assert_not_called()
        self.backend.assert_not_called()
        self.assertEqual(self.ledger.read(self.execution)["calls"], [])

    def test_caller_cannot_submit_case_policy_or_verdict_and_errors_do_not_reflect_them(self):
        for key in ("body", "guardrail", "task_completed", "security_verdict", "provider_mode"):
            request = {**self.registration, key: "private-input-marker"}
            response = self.client.post("/executions", json=request, headers=headers(CONTROL))
            self.assertEqual(response.status_code, 422)
            self.assertNotIn("private-input-marker", response.text)
        self.resolve.assert_not_called()

    def test_duplicate_registration_call_and_closed_execution_are_rejected(self):
        grant = self.register()
        self.assertEqual(self.client.post("/executions", json=self.registration,
            headers=headers(CONTROL)).status_code, 409)
        self.assertEqual(self.invoke(grant["capability"]).status_code, 200)
        self.assertEqual(self.invoke(grant["capability"]).status_code, 409)
        self.client.post(f"/executions/{self.execution}/close", json={}, headers=headers(CONTROL))
        self.assertEqual(self.invoke(grant["capability"]).status_code, 409)
        self.assertEqual(self.backend.call_count, 1)

    def test_bad_arguments_are_error_with_no_backend_dispatch(self):
        grant = self.register()
        response = self.invoke(grant["capability"], payload={})
        self.assertEqual(response.status_code, 502)
        self.backend.assert_not_called()
        self.assertEqual(self.ledger.read(self.execution)["calls"][0]["state"], "error")

    def test_health_does_not_resolve_cases_or_contact_backend(self):
        self.assertEqual(self.client.get("/readyz").json()["provider_check"], "not-run")
        self.resolve.assert_not_called()
        self.factory.assert_not_called()
        self.backend.assert_not_called()

    def test_missing_registration_is_not_replaced_with_default_case(self):
        self.resolve.side_effect = RuntimeError("private-state")
        response = self.client.post("/executions", json=self.registration, headers=headers(CONTROL))
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private-state", response.text)
        self.backend.assert_not_called()

    def test_invalid_shared_credentials_cannot_create_app(self):
        for control, verifier in ((CONTROL, CONTROL), ("short", VERIFIER)):
            with self.assertRaises(ValueError):
                create_app(self.ledger, control_token=control, verifier_token=verifier,
                           resolve_execution=self.resolve, invocation_for=self.factory)


if __name__ == "__main__":
    unittest.main()
