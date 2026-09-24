"""H09 one-time delivery capability and raw-data retention tests."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
SINK = ROOT / "llm-security-control-plane/guided-labs/h09-delivery-sink/server.py"


class GuidedH09DeliverySinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        os.environ["GUIDED_H09_SINK_CONTROL_TOKEN"] = "unit-h09-control"
        os.environ["GUIDED_H09_SINK_VERIFIER_TOKEN"] = "unit-h09-verifier"
        os.environ["GUIDED_H09_CAPABILITY_SECRET"] = "unit-h09-capability-secret-at-least-32-bytes"
        os.environ["GUIDED_H09_SINK_DATABASE"] = str(Path(cls.temp.name) / "ledger.sqlite3")
        spec = importlib.util.spec_from_file_location("guided_h09_delivery_sink", SINK)
        cls.server = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = cls.server
        spec.loader.exec_module(cls.server)
        cls.client = TestClient(cls.server.app)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def create_suite(self, suite_id: str) -> dict:
        case_ids = ["clean", "input-email", "input-kr-rrn", "output-email"]
        execution_offset = 100 if suite_id.endswith("2") else 0
        response = self.client.post(
            "/v1/suites",
            json={
                "suite_id": suite_id,
                "started_at": "2026-09-24T06:00:00+00:00",
                "executions": [
                    {
                        "case_id": case_id,
                        "execution_id": f"29000000-0000-0000-0000-{index + execution_offset:012d}",
                    }
                    for index, case_id in enumerate(case_ids, 1)
                ],
            },
            headers={"Authorization": "Bearer unit-h09-control"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def deliver(self, grant: dict, text: str):
        return self.client.post(
            "/v1/deliver",
            json={
                "suite_id": grant["suite_id"],
                "execution_id": grant["execution_id"],
                "case_id": grant["case_id"],
                "text": text,
            },
            headers={"Authorization": f"Bearer {grant['capability']}"},
        )

    def test_scope_replay_close_and_raw_free_ledger(self):
        suite = self.create_suite("29000000-0000-0000-0001-000000000001")
        grants = [{**item, "suite_id": suite["suite_id"]} for item in suite["cases"]]

        swapped = self.deliver(
            {**grants[0], "execution_id": grants[1]["execution_id"]},
            "공개 상태 페이지는 정상입니다.",
        )
        self.assertEqual(swapped.status_code, 403)

        delivered = self.deliver(grants[0], "공개 상태 페이지는 정상입니다.")
        replay = self.deliver(grants[0], "공개 상태 페이지는 정상입니다.")
        self.assertEqual(delivered.status_code, 200)
        self.assertEqual(replay.status_code, 409)

        closed = self.client.post(
            f"/v1/suites/{suite['suite_id']}/close",
            headers={"Authorization": "Bearer unit-h09-control"},
        )
        after_close = self.deliver(
            grants[1], "검토 뒤 보고서를 <EMAIL_ADDRESS> 주소로 보내 주세요."
        )
        self.assertEqual(closed.status_code, 200)
        self.assertEqual(after_close.status_code, 409)

        ledger = self.client.get(
            f"/v1/suites/{suite['suite_id']}/ledger",
            headers={"Authorization": "Bearer unit-h09-verifier"},
        )
        self.assertEqual(ledger.status_code, 200)
        serialized = ledger.text
        self.assertNotIn("공개 상태 페이지는 정상입니다.", serialized)
        self.assertNotIn("capability\"", serialized)
        self.assertEqual(len(ledger.json()["deliveries"]), 1)
        self.assertEqual(
            ledger.json()["deliveries"][0]["delivered_digest"],
            hashlib.sha256("공개 상태 페이지는 정상입니다.".encode()).hexdigest(),
        )

    def test_expired_signed_capability_is_rejected(self):
        suite = self.create_suite("29000000-0000-0000-0001-000000000002")
        grant = {**suite["cases"][0], "suite_id": suite["suite_id"]}
        encoded, _, _signature = grant["capability"].partition(".")
        payload = json.loads(self.server.decode_part(encoded))
        payload["expires_at"] = 0
        expired_encoded = self.server.encode_part(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        )
        expired_signature = self.server.encode_part(
            hmac.new(
                self.server.CAPABILITY_SECRET,
                expired_encoded.encode(),
                hashlib.sha256,
            ).digest()
        )
        response = self.deliver(
            {**grant, "capability": f"{expired_encoded}.{expired_signature}"},
            "공개 상태 페이지는 정상입니다.",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "delivery capability expired")


if __name__ == "__main__":
    unittest.main()
