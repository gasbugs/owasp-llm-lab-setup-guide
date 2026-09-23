"""H03 learner synchronization application contract tests."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "llm-security-control-plane/guided-labs/h03-ingestion-search/server.py"


class FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload


class GuidedH03IngestionSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        os.environ["GUIDED_H03_GATEWAY_TOKEN"] = "h03-gateway"
        os.environ["GUIDED_CONTROL_LAB03_TOKEN"] = "h03-control"
        os.environ["GUIDED_VERIFIER_LAB03_TOKEN"] = "h03-verifier"
        os.environ["GUIDED_H03_DATABASE"] = str(Path(cls.temp.name) / "receipts.sqlite3")
        spec = importlib.util.spec_from_file_location("guided_h03_sync_app", SOURCE)
        cls.server = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = cls.server
        spec.loader.exec_module(cls.server)
        cls.client = TestClient(cls.server.app)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_starter_retrieves_while_current_job_is_in_progress(self):
        execution_id = "11111111-1111-1111-1111-111111111111"
        responses = {
            "post": [
                FakeResponse({"ingestion_job_id": "JOB1", "status": "STARTING"}),
                FakeResponse(
                    {
                        "provider_request_id": "retrieve-1",
                        "source_uris": ["s3://h03/revoked-policy.md"],
                        "document_ids": ["old-document"],
                    }
                ),
            ],
            "get": FakeResponse({"ingestion_job_id": "JOB1", "status": "IN_PROGRESS"}),
        }
        with patch.object(self.server.httpx, "post", side_effect=responses["post"]), patch.object(
            self.server.httpx, "get", return_value=responses["get"]
        ):
            started = self.client.post(
                "/v1/sync",
                json={"execution_id": execution_id, "started_at": "2026-09-23T00:00:00+00:00"},
                headers={"Authorization": "Bearer h03-control"},
            )
            searched = self.client.post(
                "/v1/search",
                json={"execution_id": execution_id, "phase": "early"},
                headers={"Authorization": "Bearer h03-control"},
            )
        self.assertEqual(started.status_code, 200)
        self.assertEqual(searched.status_code, 200)
        self.assertTrue(searched.json()["retrieval_called"])
        self.assertEqual(searched.json()["job_status"], "IN_PROGRESS")

    def test_job_id_is_loaded_from_server_state(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('current_job(request.execution_id)', source)
        self.assertIn("TODO(H03)", source)
        self.assertIn("return True", source)
        self.assertNotIn("boto3", source)

    def test_runtime_has_no_aws_credentials(self):
        compose = yaml.safe_load(
            (ROOT / "examples/security-monitoring/compose.guided.yaml").read_text(
                encoding="utf-8"
            )
        )
        service = compose["services"]["guided-h03-sync-app"]
        self.assertNotIn("/tmp/.aws", str(service))
        self.assertNotIn("AWS_PROFILE", str(service))


if __name__ == "__main__":
    unittest.main()
