"""Packaged production runner wiring; no downstream or AWS calls during startup."""
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

CONTROL = Path(__file__).resolve().parents[2] / "llm-security-control-plane"
sys.path.insert(0, str(CONTROL / "guided-labs/h12-application-pipeline"))
from run_server import configured_app
sys.path.insert(0, str(CONTROL / "guided-labs/h12-protected-services"))
from context_store import ContextStore


class ConfiguredRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.contract = CONTROL / "guided-contracts/p12.json"
        self.environment = {"GUIDED_CONTROL_LAB12_TOKEN": "fixture-control",
                            "GUIDED_VERIFIER_LAB12_TOKEN": "fixture-verifier",
                            "GUIDED_H12_DATABASE": str(Path(self.temp.name) / "receipt.sqlite3")}
        for service in ("CONTEXT", "PRIVACY", "NEMO", "GATEWAY"):
            for role in (("CONTROL",) if service == "GATEWAY" else ("CONTROL", "SERVICE")):
                self.environment[f"GUIDED_P12_{service}_{role}_TOKEN"] = f"fixture-{service}-{role}"

    def client(self):
        return TestClient(configured_app(environment=self.environment, contract_path=self.contract))

    def test_startup_and_readiness_do_not_connect_to_products(self):
        with patch("workflow.httpx.Client", side_effect=AssertionError("no startup network")):
            client = self.client()
            self.assertEqual(client.get("/readyz").status_code, 200)
            build = client.get("/v1/build-info", headers={"Authorization": "Bearer fixture-verifier"}).json()
        contract = json.loads(self.contract.read_text())
        inputs = [spec["input"] for spec in contract["specifications"]]
        expected = hashlib.sha256(json.dumps({"cases": inputs, "documents": contract["documents"]},
                                            sort_keys=True, ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        self.assertEqual(build["build"]["contract_digest"], expected)
        self.assertEqual(build["case_ids"], [item["case_id"] for item in inputs])
        self.assertEqual(len(inputs), 8)

    def test_missing_problem_credential_is_not_silently_defaulted(self):
        del self.environment["GUIDED_P12_NEMO_SERVICE_TOKEN"]
        with self.assertRaises(ValueError):
            self.client()

    def test_wrong_contract_identity_is_rejected(self):
        data = json.loads(self.contract.read_text())
        data["practice_id"] = "P11"
        self.contract = Path(self.temp.name) / "wrong.json"
        self.contract.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            self.client()

    def test_no_cases_or_verdicts_can_be_submitted_by_caller(self):
        client = self.client()
        for field, value in (("cases", []), ("task_completed", True), ("message", "replacement")):
            response = client.post("/v1/run", headers={"Authorization": "Bearer fixture-control"},
                                   json={"suite_id": str(uuid4()), field: value})
            self.assertEqual(response.status_code, 422)
        self.assertEqual(client.post("/v1/run", json={"suite_id": str(uuid4())}).status_code, 401)

    def test_canonical_search_cases_do_not_mix_documents_or_tenants(self):
        contract = json.loads(self.contract.read_text())
        expected = {"normal": ["account"], "input-pii": ["account"],
                    "retrieval-block": ["review"], "output-block": ["output"], "no-hits": []}
        store = ContextStore(Path(self.temp.name) / "context.sqlite3", "a" * 64)
        for spec in contract["specifications"]:
            case = spec["input"]
            if case["case_id"] not in expected:
                continue
            with self.subTest(case=case["case_id"]):
                suite, execution = str(uuid4()), str(uuid4())
                registered = store.register(suite, [execution], contract["documents"])
                store.execute(suite, execution, "authenticate", registered["credentials"]["reader"])
                store.execute(suite, execution, "authorize", case["tenant"])
                query = case["message"].replace("learner@example.com", "<EMAIL_ADDRESS>")
                result = store.execute(suite, execution, "retrieval", query)
                self.assertEqual([hit["document_id"] for hit in result["evidence"]["hits"]], expected[case["case_id"]])
                self.assertTrue(all(hit["tenant"] == "team-a" for hit in result["evidence"]["hits"]))
                store.close(suite)


if __name__ == "__main__":
    unittest.main()
