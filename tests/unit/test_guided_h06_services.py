import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest
import uuid

from fastapi.testclient import TestClient


ROOT = pathlib.Path(__file__).resolve().parents[2]
PROVIDER_PATH = ROOT / "llm-security-control-plane/guided-labs/h06-action-provider/provider.py"


def load_provider(database: pathlib.Path):
    values = {
        "GUIDED_H06_PROVIDER_CONTROL_TOKEN": "control-token",
        "GUIDED_H06_PROVIDER_ACTION_TOKEN": "action-token",
        "GUIDED_H06_PROVIDER_VERIFIER_TOKEN": "verifier-token",
        "GUIDED_H06_CAPABILITY_SECRET": "capability-secret-with-at-least-32-bytes",
        "GUIDED_H06_PROVIDER_DATABASE": str(database),
    }
    os.environ.update(values)
    module_name = f"guided_h06_provider_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, PROVIDER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class H06ProviderTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.provider = load_provider(pathlib.Path(self.tempdir.name) / "provider.sqlite3")
        self.client = TestClient(self.provider.app)
        self.suite_id = str(uuid.uuid4())
        self.executions = [
            {"case_id": case_id, "execution_id": str(uuid.uuid4())}
            for case_id in self.provider.CASE_ORDER
        ]

    def tearDown(self):
        self.tempdir.cleanup()

    def create_suite(self):
        return self.client.post(
            "/v1/suites",
            headers={"Authorization": "Bearer control-token"},
            json={
                "suite_id": self.suite_id,
                "started_at": "2026-09-23T00:00:00+00:00",
                "executions": self.executions,
            },
        )

    def test_fixed_suite_issues_four_exact_capabilities(self):
        response = self.create_suite()
        self.assertEqual(response.status_code, 200)
        cases = response.json()["cases"]
        self.assertEqual([case["case_id"] for case in cases], list(self.provider.CASE_ORDER))
        self.assertIsNone(cases[-1]["action_id"])
        self.assertEqual(response.json()["starting_balance"], 10_000)

    def test_write_actions_decrement_and_append_effects(self):
        cases = self.create_suite().json()["cases"]
        for case in cases[:3]:
            response = self.client.post(
                "/v1/actions/execute",
                headers={"Authorization": "Bearer action-token"},
                json={
                    "suite_id": self.suite_id,
                    "execution_id": case["execution_id"],
                    "case_id": case["case_id"],
                    "action_id": case["action_id"],
                    "capability": case["capability"],
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
        ledger = self.client.get(
            f"/v1/suites/{self.suite_id}/ledger",
            headers={"Authorization": "Bearer verifier-token"},
        ).json()
        self.assertEqual(
            [call["action_id"] for call in ledger["calls"]],
            [
                "get_account_balance",
                "transfer_training_funds",
                "get_account_balance_and_transfer",
            ],
        )
        self.assertEqual(len(ledger["effects"]), 2)
        self.assertEqual(ledger["current_balance"], 9_800)
        self.assertIsNone(ledger["capabilities"][-1]["used_at"])

    def test_capability_is_exact_and_one_time(self):
        case = self.create_suite().json()["cases"][0]
        request = {
            "suite_id": self.suite_id,
            "execution_id": case["execution_id"],
            "case_id": case["case_id"],
            "action_id": case["action_id"],
            "capability": case["capability"],
        }
        first = self.client.post(
            "/v1/actions/execute",
            headers={"Authorization": "Bearer action-token"},
            json=request,
        )
        self.assertEqual(first.status_code, 200)
        second = self.client.post(
            "/v1/actions/execute",
            headers={"Authorization": "Bearer action-token"},
            json=request,
        )
        self.assertEqual(second.status_code, 409)
        request["execution_id"] = str(uuid.uuid4())
        mismatch = self.client.post(
            "/v1/actions/execute",
            headers={"Authorization": "Bearer action-token"},
            json=request,
        )
        self.assertEqual(mismatch.status_code, 403)

    def test_browser_cannot_choose_suite_shape_or_read_ledger(self):
        malformed = self.client.post(
            "/v1/suites",
            headers={"Authorization": "Bearer control-token"},
            json={
                "suite_id": self.suite_id,
                "started_at": "2026-09-23T00:00:00+00:00",
                "executions": self.executions[:-1],
            },
        )
        self.assertEqual(malformed.status_code, 422)
        self.create_suite()
        denied = self.client.get(f"/v1/suites/{self.suite_id}/ledger")
        self.assertEqual(denied.status_code, 401)


if __name__ == "__main__":
    unittest.main()
