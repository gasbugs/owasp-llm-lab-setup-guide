import importlib.util
import json
import os
import pathlib
import shutil
import sys
import tempfile
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from fastapi.testclient import TestClient


ROOT = pathlib.Path(__file__).resolve().parents[2]
LEARNER_SOURCE = ROOT / "llm-security-control-plane/guided-labs/h07-content-safety"
CONTROL_TOKEN = "h07-control-token"
VERIFIER_TOKEN = "h07-verifier-token"
CAPABILITIES = {
    "normal-content": "normal-content-safety-" + "c" * 48,
    "normal-main": "normal-main-" + "m" * 48,
    "risk-content": "risk-content-safety-" + "r" * 48,
    "risk-main": "risk-main-" + "x" * 48,
}


class FakeGatewayHandler(BaseHTTPRequestHandler):
    calls = []

    def do_POST(self):
        if self.path != "/v1/h07/chat/completions":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        authorization = self.headers.get("Authorization")
        token = (authorization or "").removeprefix("Bearer ")
        if token not in CAPABILITIES.values():
            self.send_error(401)
            return

        role = "content_safety" if "content-safety" in token else "main"
        case_id = "normal-phishing-defense" if token.startswith("normal-") else "risk-phishing-kit"
        self.__class__.calls.append(
            {"role": role, "case_id": case_id, "model": payload.get("model")}
        )
        if role == "content_safety":
            content = (
                '{"User Safety":"safe"}'
                if case_id == "normal-phishing-defense"
                else '{"User Safety":"unsafe","Safety Categories":"S16, S17"}'
            )
        else:
            content = "fake main response"
        body = json.dumps(
            {
                "id": f"fake-{len(self.__class__.calls)}",
                "object": "chat.completion",
                "model": payload["model"],
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 12,
                    "completion_tokens": 4,
                    "total_tokens": 16,
                },
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


FIXED_CONFIG = """# CUSTOM FILE
# Format reference: https://docs.nvidia.com/nemo/guardrails/latest/configure-rails/configuration-guide.html
# Upstream format license: Apache-2.0

models:
  - type: main
    engine: openai
    model: us.amazon.nova-lite-v1:0#h07-main
    parameters:
      temperature: 0.0
      max_tokens: 120
  - type: content_safety
    engine: openai
    model: us.amazon.nova-lite-v1:0#h07-content-safety

rails:
  input:
    flows:
      - content safety check input $model=content_safety
"""


class H07LearnerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gateway = ThreadingHTTPServer(("127.0.0.1", 0), FakeGatewayHandler)
        cls.gateway_thread = threading.Thread(target=cls.gateway.serve_forever, daemon=True)
        cls.gateway_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.gateway.shutdown()
        cls.gateway.server_close()
        cls.gateway_thread.join(timeout=5)

    def setUp(self):
        FakeGatewayHandler.calls = []
        self.tempdir = tempfile.TemporaryDirectory()
        self.learner_root = pathlib.Path(self.tempdir.name) / "h07-content-safety"
        shutil.copytree(LEARNER_SOURCE, self.learner_root)
        os.environ.update(
            {
                "GUIDED_CONTROL_LAB07_TOKEN": CONTROL_TOKEN,
                "GUIDED_VERIFIER_LAB07_TOKEN": VERIFIER_TOKEN,
                "GUIDED_H07_GATEWAY_URL": f"http://127.0.0.1:{self.gateway.server_port}",
                "GUIDED_H07_DATABASE": str(self.learner_root / "receipts.sqlite3"),
            }
        )
        name = f"guided_h07_learner_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(name, self.learner_root / "server.py")
        self.module = importlib.util.module_from_spec(spec)
        sys.modules[name] = self.module
        spec.loader.exec_module(self.module)
        self.client = TestClient(self.module.app)

    def tearDown(self):
        self.client.close()
        self.tempdir.cleanup()

    def run_suite(self):
        suite_id = str(uuid.uuid4())
        response = self.client.post(
            "/v1/run",
            headers={"Authorization": f"Bearer {CONTROL_TOKEN}"},
            json={
                "suite_id": suite_id,
                "started_at": "2026-09-23T00:00:00+00:00",
                "cases": [
                    {
                        "case_id": "normal-phishing-defense",
                        "execution_id": str(uuid.uuid4()),
                        "content_safety_capability": CAPABILITIES["normal-content"],
                        "main_capability": CAPABILITIES["normal-main"],
                    },
                    {
                        "case_id": "risk-phishing-kit",
                        "execution_id": str(uuid.uuid4()),
                        "content_safety_capability": CAPABILITIES["risk-content"],
                        "main_capability": CAPABILITIES["risk-main"],
                    },
                ],
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        receipt = self.client.get(
            f"/v1/receipts/{suite_id}",
            headers={"Authorization": f"Bearer {VERIFIER_TOKEN}"},
        )
        self.assertEqual(receipt.status_code, 200, receipt.text)
        return receipt.json()

    def test_starter_calls_only_main_for_both_cases(self):
        receipt = self.run_suite()
        self.assertEqual(
            [(item["case_id"], item["role"]) for item in FakeGatewayHandler.calls],
            [
                ("normal-phishing-defense", "main"),
                ("risk-phishing-kit", "main"),
            ],
        )
        self.assertEqual([len(case["llm_calls"]) for case in receipt["cases"]], [1, 1])
        self.assertTrue(
            all(
                not any(rail["type"] == "input" for rail in case["activated_rails"])
                for case in receipt["cases"]
            )
        )

    def test_fixed_config_runs_guard_then_stops_risk_before_main(self):
        (self.learner_root / "config/config.yml").write_text(FIXED_CONFIG)
        receipt = self.run_suite()
        self.assertEqual(
            [(item["case_id"], item["role"]) for item in FakeGatewayHandler.calls],
            [
                ("normal-phishing-defense", "content_safety"),
                ("normal-phishing-defense", "main"),
                ("risk-phishing-kit", "content_safety"),
            ],
        )
        normal, risk = receipt["cases"]
        self.assertEqual(len(normal["llm_calls"]), 2)
        self.assertEqual(len(risk["llm_calls"]), 1)
        risk_rail = next(
            rail
            for rail in risk["activated_rails"]
            if rail["name"] == "content safety check input $model=content_safety"
        )
        self.assertTrue(risk_rail["stop"])
        self.assertIn("content_safety_check_input", risk_rail["actions"])

    def test_receipt_projects_logs_and_never_persists_secrets_or_raw_text(self):
        (self.learner_root / "config/config.yml").write_text(FIXED_CONFIG)
        receipt = self.run_suite()
        encoded = json.dumps(receipt, ensure_ascii=False)
        for secret in CAPABILITIES.values():
            self.assertNotIn(secret, encoded)
        self.assertNotIn("피싱 메일을 식별", encoded)
        self.assertNotIn("fake main response", encoded)
        self.assertNotIn('"prompt"', encoded)
        self.assertNotIn('"completion"', encoded)
        self.assertNotIn('"raw_response"', encoded)
        self.assertRegex(receipt["cases"][0]["content_safety_capability_digest"], r"^[0-9a-f]{64}$")
        self.assertRegex(receipt["cases"][0]["response_digest"], r"^[0-9a-f]{64}$")

    def test_api_rejects_wrong_order_and_protects_evidence(self):
        denied = self.client.get("/v1/build-info")
        self.assertEqual(denied.status_code, 401)
        payload = {
            "suite_id": str(uuid.uuid4()),
            "started_at": "2026-09-23T00:00:00+00:00",
            "cases": [
                {
                    "case_id": case_id,
                    "execution_id": str(uuid.uuid4()),
                    "content_safety_capability": "c" * 48,
                    "main_capability": "m" * 48,
                }
                for case_id in reversed(self.module.CASE_ORDER)
            ],
        }
        rejected = self.client.post(
            "/v1/run",
            headers={"Authorization": f"Bearer {CONTROL_TOKEN}"},
            json=payload,
        )
        self.assertEqual(rejected.status_code, 422)


if __name__ == "__main__":
    unittest.main()
