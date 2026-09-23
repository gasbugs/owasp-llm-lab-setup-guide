"""H03 provider boundary contract tests."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
GATEWAY = ROOT / "llm-security-control-plane/guided-bedrock-gateway"


class GuidedH03GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        values = {
            "GUIDED_PROVIDER_MODE": "contract",
            "GUIDED_GATEWAY_DATABASE": str(Path(cls.temp.name) / "gateway.sqlite3"),
            "GUIDED_LAB01_GATEWAY_TOKEN": "lab01",
            "GUIDED_NEMO_GATEWAY_TOKEN": "nemo",
            "GUIDED_VERIFIER_GATEWAY_TOKEN": "verifier",
            "GUIDED_H02_GATEWAY_TOKEN": "h02",
            "GUIDED_LAB02_PROVISION_TOKEN": "h02-provision",
            "GUIDED_H03_GATEWAY_TOKEN": "h03",
            "GUIDED_LAB03_PROVISION_TOKEN": "h03-provision",
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

    def test_contract_exposes_revoked_then_current_source(self):
        provision = self.client.post(
            "/v1/h03/provision",
            json={"execution_id": "11111111-1111-1111-1111-111111111111"},
            headers={"Authorization": "Bearer h03-provision"},
        )
        self.assertEqual(provision.status_code, 200)
        self.assertEqual(provision.json()["status"], "READY_FOR_SYNC")

        execution_id = "22222222-2222-2222-2222-222222222222"
        started = self.client.post(
            "/v1/h03/ingestions",
            json={"execution_id": execution_id},
            headers={"Authorization": "Bearer h03"},
        )
        job_id = started.json()["ingestion_job_id"]
        first_status = self.client.get(
            f"/v1/h03/ingestions/{job_id}",
            headers={"Authorization": "Bearer h03"},
        )
        self.assertEqual(first_status.json()["status"], "IN_PROGRESS")
        early = self.client.post(
            "/v1/h03/retrievals",
            json={
                "execution_id": execution_id,
                "phase": "early",
                "ingestion_job_id": job_id,
            },
            headers={"Authorization": "Bearer h03"},
        )
        self.assertIn("revoked-policy.md", early.json()["source_uris"][0])

        second_status = self.client.get(
            f"/v1/h03/ingestions/{job_id}",
            headers={"Authorization": "Bearer h03"},
        )
        self.assertEqual(second_status.json()["status"], "COMPLETE")
        final = self.client.post(
            "/v1/h03/retrievals",
            json={
                "execution_id": execution_id,
                "phase": "final",
                "ingestion_job_id": job_id,
            },
            headers={"Authorization": "Bearer h03"},
        )
        self.assertIn("current-policy.md", final.json()["source_uris"][0])
        self.assertNotIn("revoked-policy.md", final.text)

    def test_browser_cannot_choose_resource_or_job_state(self):
        rejected = self.client.post(
            "/v1/h03/provision",
            json={
                "execution_id": "33333333-3333-3333-3333-333333333333",
                "bucket": "attacker-bucket",
            },
            headers={"Authorization": "Bearer h03-provision"},
        )
        self.assertEqual(rejected.status_code, 422)
        denied = self.client.post(
            "/v1/h03/ingestions",
            json={"execution_id": "44444444-4444-4444-4444-444444444444"},
            headers={"Authorization": "Bearer wrong"},
        )
        self.assertEqual(denied.status_code, 401)


if __name__ == "__main__":
    unittest.main()
