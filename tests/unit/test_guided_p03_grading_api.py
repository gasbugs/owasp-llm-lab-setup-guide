"""Caller cannot supply P03 expected inputs, source IDs or verdicts."""
import threading
import unittest
from unittest.mock import Mock
from uuid import uuid4

from fastapi.testclient import TestClient
from test_guided_p03_suite_verification import grading_api


class GradingApiTests(unittest.TestCase):
    def setUp(self):
        self.verification = Mock(app_token="app-reader", gateway_token="gateway-reader")
        self.verification.cases = [{"case_id": "current-complete"}]
        self.suite = str(uuid4())
        self.verification.collect.return_value = {"case_contract_verified": True, "provider_mode": "contract",
                                                  "root": {"suite_id": self.suite},
                                                  "cases": [{"case_id": "current-complete", "case_verified": True}]}
        self.headers = {"Authorization": "Bearer control-fixture"}
        self.client = TestClient(grading_api.create_app(self.verification, control_token="control-fixture"))
        self.addCleanup(self.client.close)

    def post(self, **extra):
        return self.client.post("/v1/verify/p03", headers=self.headers, json={"suite_id": self.suite, **extra})

    def test_health_does_not_collect_or_call_a_provider(self):
        self.assertEqual(self.client.get("/readyz").json()["provider_check"], "not-run")
        self.verification.collect.assert_not_called()

    def test_only_suite_id_reaches_server_configured_verification(self):
        result = self.post().json()
        self.verification.collect.assert_called_once_with(self.suite)
        self.assertTrue(result["task_completed"])
        self.assertEqual(result["security_verdict"], "PASS")
        self.assertEqual(result["provider_mode"], "contract")

    def test_caller_fields_are_rejected_without_echo_or_collection(self):
        for extra in ({"task_completed": True}, {"security_verdict": "PASS"}, {"source_digest": "f" * 64},
                      {"expected": []}, {"current_job_id": "previous"}, {"token": "do-not-echo"}):
            response = self.post(**extra)
            self.assertEqual(response.status_code, 422)
            self.assertNotIn("do-not-echo", response.text)
        self.verification.collect.assert_not_called()

    def test_wrong_or_missing_credentials_cannot_grade(self):
        for token in ("app-reader", "gateway-reader", "wrong"):
            response = self.client.post("/v1/verify/p03", json={"suite_id": self.suite},
                                        headers={"Authorization": "Bearer " + token})
            self.assertEqual(response.status_code, 401)
        self.assertEqual(self.client.post("/v1/verify/p03", json={"suite_id": self.suite}).status_code, 401)
        self.verification.collect.assert_not_called()

    def test_errors_wrong_suite_or_unknown_mode_never_reuse_success(self):
        self.assertTrue(self.post().json()["task_completed"])
        for result in ({"case_contract_verified": False}, {"case_contract_verified": True, "provider_mode": "contract",
                      "root": {"suite_id": self.suite}, "cases": []}, {"case_contract_verified": True, "provider_mode": "aws",
                      "root": {"suite_id": str(uuid4())}}, {"case_contract_verified": True, "provider_mode": "unknown"}):
            self.verification.collect.return_value = result
            reply = self.post().json()
            self.assertFalse(reply["task_completed"])
            self.assertEqual(reply["security_verdict"], "ERR")
        self.verification.collect.side_effect = RuntimeError("secret diagnostic")
        reply = self.post()
        self.assertEqual(reply.json()["security_verdict"], "ERR")
        self.assertNotIn("secret", reply.text)

    def test_concurrent_grading_is_rejected_and_lock_released(self):
        arrived, release = threading.Event(), threading.Event()
        def wait(_suite):
            arrived.set()
            if not release.wait(5):
                raise TimeoutError()
            raise RuntimeError("controlled failure")
        self.verification.collect.side_effect = wait
        thread = threading.Thread(target=self.post)
        thread.start()
        try:
            self.assertTrue(arrived.wait(5))
            self.assertEqual(self.post().status_code, 409)
        finally:
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.post().status_code, 200)

    def test_control_cannot_share_read_only_credentials(self):
        with self.assertRaises(ValueError):
            grading_api.create_app(self.verification, control_token="app-reader")


if __name__ == "__main__":
    unittest.main()
