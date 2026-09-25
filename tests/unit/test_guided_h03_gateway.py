"""H03 provider boundary contract tests."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
GATEWAY = ROOT / "llm-security-control-plane/guided-bedrock-gateway"
VERIFIER_TOKEN = "verifier-" * 8
H04_TOKEN = "h04-" * 8
H04_PROVISION_TOKEN = "h04-provision-" * 4


class GuidedH03GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        values = {
            "GUIDED_PROVIDER_MODE": "contract",
            "GUIDED_GATEWAY_DATABASE": str(Path(cls.temp.name) / "gateway.sqlite3"),
            "GUIDED_LAB01_GATEWAY_TOKEN": "lab01",
            "GUIDED_NEMO_GATEWAY_TOKEN": "nemo",
            "GUIDED_VERIFIER_GATEWAY_TOKEN": VERIFIER_TOKEN,
            "GUIDED_H02_GATEWAY_TOKEN": "h02",
            "GUIDED_LAB02_PROVISION_TOKEN": "h02-provision",
            "GUIDED_H03_GATEWAY_TOKEN": "h03",
            "GUIDED_LAB03_PROVISION_TOKEN": "h03-provision",
            "GUIDED_H04_GATEWAY_TOKEN": H04_TOKEN,
            "GUIDED_LAB04_PROVISION_TOKEN": H04_PROVISION_TOKEN,
            "GUIDED_H07_GATEWAY_CONTROL_TOKEN": "h07-control",
            "GUIDED_H07_GATEWAY_VERIFIER_TOKEN": "h07-verifier",
            "GUIDED_H07_CAPABILITY_SECRET": "h07-capability-secret-at-least-32-bytes",
            "GUIDED_H08_GATEWAY_CONTROL_TOKEN": "h08-control",
            "GUIDED_H08_GATEWAY_VERIFIER_TOKEN": "h08-verifier",
            "GUIDED_H08_CAPABILITY_SECRET": "h08-capability-secret-at-least-32-bytes",
            "GUIDED_H10_GATEWAY_TOKEN": "h10",
            "GUIDED_H10_GATEWAY_VERIFIER_TOKEN": "h10-verifier",
            "GUIDED_H11_GATEWAY_TOKEN": "h11",
            "GUIDED_H11_GATEWAY_VERIFIER_TOKEN": "h11-verifier",
        }
        os.environ.update(values)
        sys.path.insert(0, str(GATEWAY))
        spec = importlib.util.spec_from_file_location(
            "guided_bedrock_gateway_h03_tests", GATEWAY / "server.py"
        )
        cls.server = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = cls.server
        spec.loader.exec_module(cls.server)
        cls.client = TestClient(cls.server.app)

    @classmethod
    def tearDownClass(cls):
        sys.path.remove(str(GATEWAY))
        cls.temp.cleanup()

    def test_retired_execution_routes_do_not_call_backends(self):
        backend = sys.modules["h03_backend"]
        routes = [
            ("POST", "/v1/h03/provision", "h03-provision"),
            ("POST", "/v1/h03/ingestions", "h03"),
            ("GET", "/v1/h03/ingestions/historical-job", "h03"),
            ("POST", "/v1/h03/retrievals", "h03"),
        ]
        with patch.object(backend, "connect") as connect:
            for method, path, token in routes:
                with self.subTest(path=path):
                    response = self.client.request(method, path,
                        headers={"Authorization": "Bearer " + token})
                    self.assertEqual(response.status_code, 410)
                    self.assertEqual(self.client.request(method, path).status_code, 401)
            connect.assert_not_called()

    def test_historical_job_is_a_read_only_saved_snapshot(self):
        backend = sys.modules["h03_backend"]
        job = {"ingestion_job_id": "historical-job", "status": "IN_PROGRESS"}
        with patch.object(backend, "load_state", return_value={"current_job": job}):
            response = self.client.get("/v1/h03/jobs/historical-job",
                headers={"Authorization": "Bearer " + VERIFIER_TOKEN})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), job)
            missing = self.client.get("/v1/h03/jobs/different-job",
                headers={"Authorization": "Bearer " + VERIFIER_TOKEN})
            self.assertEqual(missing.status_code, 404)

    def test_historical_reads_preserve_saved_rows_without_provider_calls(self):
        backend = sys.modules["h03_backend"]
        state = {"provider_mode": "aws", "status": "SYNCING",
                 "current_job": {"ingestion_job_id": "saved-job", "status": "QUEUED"}}
        receipt = {"execution_id": "saved-execution", "phase": "early",
                   "provider_request_id": "saved-request", "provider_mode": "aws"}
        with backend.connect() as database:
            database.execute("INSERT OR REPLACE INTO resource_state VALUES('h03',?)",
                             (json.dumps(state),))
            database.execute("INSERT OR REPLACE INTO h03_retrieval_evidence VALUES(?,?,?,?)",
                             ("saved-execution", "early", "saved-request", json.dumps(receipt)))
            before = list(database.iterdump())
        with patch("boto3.client", side_effect=AssertionError("historical reads must be local")):
            for path, expected in (
                ("/v1/h03/resources", state),
                ("/v1/h03/jobs/saved-job", state["current_job"]),
                ("/v1/h03/retrievals/saved-execution/early", receipt),
            ):
                with self.subTest(path=path):
                    response = self.client.get(path, headers={"Authorization": "Bearer " + VERIFIER_TOKEN})
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json(), expected)
                    for token in ("h03", "h03-provision", "wrong"):
                        self.assertEqual(self.client.get(path, headers={
                            "Authorization": "Bearer " + token}).status_code, 401)
            self.assertEqual(self.client.get("/v1/h03/retrievals/missing/early",
                headers={"Authorization": "Bearer " + VERIFIER_TOKEN}).status_code, 404)
        with backend.connect() as database:
            self.assertEqual(list(database.iterdump()), before)

    def test_missing_history_is_not_synthesized(self):
        backend = sys.modules["h03_backend"]
        with patch.object(backend, "load_state", return_value=None):
            response = self.client.get("/v1/h03/resources",
                headers={"Authorization": "Bearer " + VERIFIER_TOKEN})
            self.assertEqual(response.json(), {"status": "MISSING", "region": backend.AWS_REGION})
            self.assertEqual(self.client.get("/v1/h03/jobs/missing",
                headers={"Authorization": "Bearer " + VERIFIER_TOKEN}).status_code, 404)

    def test_retired_h04_routes_cannot_execute_or_provision(self):
        backend = sys.modules["h04_backend"]
        with patch.object(backend, "connect") as connect, patch(
            "boto3.client", side_effect=AssertionError("retired routes must not call AWS")
        ):
            for path, token in (
                ("/v1/h04/provision", H04_PROVISION_TOKEN),
                ("/v1/h04/apply", H04_TOKEN),
                ("/v1/h04/converse", H04_TOKEN),
            ):
                for body in ({}, {"attach_guardrail": True, "course_verdict": "PASS"}):
                    with self.subTest(path=path, body=body):
                        response = self.client.post(path, json=body,
                            headers={"Authorization": "Bearer " + token})
                        self.assertEqual(response.status_code, 410)
                        self.assertEqual(self.client.post(path, json=body).status_code, 401)
                        self.assertEqual(self.client.post(path, json=body, headers={
                            "Authorization": "Bearer " + VERIFIER_TOKEN}).status_code, 401)
            connect.assert_not_called()

    def test_h04_history_is_unchanged_and_never_calls_provider(self):
        backend = sys.modules["h04_backend"]
        state = {"status": "READY", "provider_mode": "aws",
                 "guardrail_id": "historical-guardrail", "guardrail_version": "DRAFT"}
        receipt = {"execution_id": "saved-h04", "provider_request_id": "saved-h04-request",
                   "provider_mode": "aws", "guardrail_config": None}
        with backend.connect() as database:
            database.execute("INSERT OR REPLACE INTO resource_state VALUES('h04',?)",
                             (json.dumps(state),))
            database.execute("INSERT OR REPLACE INTO h04_evidence VALUES(?,?,?)",
                             ("saved-h04", "saved-h04-request", json.dumps(receipt)))
            before = list(database.iterdump())
        with patch("boto3.client", side_effect=AssertionError("history must stay local")):
            for path, expected in (
                ("/v1/h04/resources", state), ("/v1/h04/evidence/saved-h04", receipt),
            ):
                response = self.client.get(path, headers={"Authorization": "Bearer " + VERIFIER_TOKEN})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json(), expected)
                self.assertNotIn("task_completed", response.json())
                for token in (H04_TOKEN, H04_PROVISION_TOKEN, "wrong"):
                    self.assertEqual(self.client.get(path, headers={
                        "Authorization": "Bearer " + token}).status_code, 401)
            self.assertEqual(self.client.get("/v1/h04/evidence/missing", headers={
                "Authorization": "Bearer " + VERIFIER_TOKEN}).status_code, 404)
        with backend.connect() as database:
            self.assertEqual(list(database.iterdump()), before)

    def test_missing_h04_state_is_not_synthesized(self):
        backend = sys.modules["h04_backend"]
        with patch.object(backend, "load_state", return_value=None):
            response = self.client.get("/v1/h04/resources", headers={
                "Authorization": "Bearer " + VERIFIER_TOKEN})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"status": "MISSING", "region": backend.AWS_REGION})


if __name__ == "__main__":
    unittest.main()
