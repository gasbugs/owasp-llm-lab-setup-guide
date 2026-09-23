"""H02 learner document application contract tests."""

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
SOURCE = ROOT / "llm-security-control-plane/guided-labs/h02-document-ingestion/server.py"


class FakeResponse:
    status_code = 200

    def json(self):
        return {"execution_id": "11111111-1111-1111-1111-111111111111"}


class GuidedH02DocumentAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        os.environ["GUIDED_H02_GATEWAY_TOKEN"] = "h02-gateway"
        os.environ["GUIDED_CONTROL_LAB02_TOKEN"] = "h02-control"
        os.environ["GUIDED_VERIFIER_LAB02_TOKEN"] = "h02-verifier"
        os.environ["GUIDED_H02_DATABASE"] = str(Path(cls.temp.name) / "receipts.sqlite3")
        spec = importlib.util.spec_from_file_location("guided_h02_document_app", SOURCE)
        cls.server = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = cls.server
        spec.loader.exec_module(cls.server)
        cls.client = TestClient(cls.server.app)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_starter_forwards_client_owned_object_key(self):
        body = {
            "execution_id": "11111111-1111-1111-1111-111111111111",
            "started_at": "2026-09-23T00:00:00+00:00",
            "title": "경로 변경 시도",
            "body": "클라이언트 경로 변경이 실제 Gateway 요청으로 이어지는지 확인합니다.",
            "scenario": "risk",
            "object_key": "h02/untrusted/11111111-1111-1111-1111-111111111111.md",
        }
        with patch.object(self.server.httpx, "post", return_value=FakeResponse()) as post:
            response = self.client.post(
                "/v1/documents",
                json=body,
                headers={"Authorization": "Bearer h02-control"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(post.call_args.kwargs["json"]["object_key"], body["object_key"])

    def test_empty_document_stops_before_gateway(self):
        body = {
            "execution_id": "22222222-2222-2222-2222-222222222222",
            "started_at": "2026-09-23T00:00:00+00:00",
            "title": "빈 문서",
            "body": "",
            "scenario": "normal",
        }
        with patch.object(self.server.httpx, "post") as post:
            response = self.client.post(
                "/v1/documents",
                json=body,
                headers={"Authorization": "Bearer h02-control"},
            )
        self.assertEqual(response.status_code, 422)
        post.assert_not_called()

    def test_runtime_has_no_aws_sdk_or_credentials(self):
        compose = yaml.safe_load(
            (ROOT / "examples/security-monitoring/compose.guided.yaml").read_text(
                encoding="utf-8"
            )
        )
        source = SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("import boto3", source)
        self.assertNotIn("AWS_SHARED_CREDENTIALS_FILE", source)
        h02_service = compose["services"]["guided-h02-document-app"]
        self.assertNotIn("/tmp/.aws", str(h02_service))
        self.assertNotIn("AWS_PROFILE", str(h02_service))


if __name__ == "__main__":
    unittest.main()
