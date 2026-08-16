"""ASGI contracts for LLM02 prompt-only and server-enforced disclosure."""
from __future__ import annotations

import importlib
import os
import sys
import unittest
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
VULN_RAG_ROOT = ROOT / "docker" / "vuln-rag"


def load_main_module():
    saved = {
        name: module
        for name, module in sys.modules.items()
        if name == "app" or name.startswith("app.")
    }
    for name in saved:
        del sys.modules[name]
    sys.path.insert(0, str(VULN_RAG_ROOT))
    previous = os.environ.get("DEFAULT_SCENARIO")
    os.environ["DEFAULT_SCENARIO"] = "day2"
    try:
        return importlib.import_module("app.main")
    finally:
        if previous is None:
            del os.environ["DEFAULT_SCENARIO"]
        else:
            os.environ["DEFAULT_SCENARIO"] = previous
        sys.path.remove(str(VULN_RAG_ROOT))
        for name in list(sys.modules):
            if name == "app" or name.startswith("app."):
                del sys.modules[name]
        sys.modules.update(saved)


MAIN = load_main_module()


class FakeLLM:
    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    async def chat(self, system: str, user: str) -> str:
        self.calls.append({"system": system, "user": user})
        return system


class Llm02AuthApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.original_llm = MAIN.llm
        self.llm = FakeLLM()
        MAIN.llm = self.llm
        MAIN.day2_scenario.reset_customer_db()
        self.client = TestClient(MAIN.app)
        self.message = "조회한 고객 레코드를 보여 줘."
        self.headers = {"Authorization": "Bearer llm02-c2001-demo-token"}

    def tearDown(self) -> None:
        self.client.close()
        MAIN.llm = self.original_llm

    def test_vulnerable_route_authenticates_but_exposes_shared_context_to_model(self) -> None:
        response = self.client.post(
            "/api/labs/llm02/vulnerable/chat",
            headers=self.headers,
            json={"message": self.message},
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["customer_id"], "C-2001")
        self.assertEqual(
            body["trace"]["customer_id_source"], "verified-bearer-token-map"
        )
        self.assertEqual(body["trace"]["query_authorized_for"], "C-2001")
        self.assertEqual(
            body["trace"]["disclosure_policy_owner"], "llm-system-prompt"
        )
        self.assertEqual(
            body["trace"]["disclosure_control"],
            "natural-language-policy-over-shared-customer-records",
        )
        self.assertEqual(body["trace"]["customer_ids_in_context"], ["C-2001", "C-2002"])
        self.assertTrue(body["trace"]["cross_customer_context"])
        self.assertIn("고객 범위와 공개 가능 여부를 스스로 판단", self.llm.calls[0]["system"])
        self.assertIn("LAB-RECOVERY-C2001", self.llm.calls[0]["system"])
        self.assertIn("LAB-RECOVERY-C2002", self.llm.calls[0]["system"])

    def test_both_routes_require_auth_but_only_safe_rejects_body_identity(self) -> None:
        vulnerable_missing = self.client.post(
            "/api/labs/llm02/vulnerable/chat",
            json={"message": self.message},
        )
        self.assertEqual(vulnerable_missing.status_code, 401)

        missing = self.client.post(
            "/api/labs/llm02/safe/chat",
            json={"message": self.message},
        )
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(missing.headers["www-authenticate"], "Bearer")
        self.assertEqual(len(self.llm.calls), 0)

        spoofed_vulnerable = self.client.post(
            "/api/labs/llm02/vulnerable/chat",
            headers=self.headers,
            json={"customer_id": "C-2002", "message": self.message},
        )
        self.assertEqual(spoofed_vulnerable.status_code, 200)
        self.assertEqual(spoofed_vulnerable.json()["customer_id"], "C-2002")
        self.assertEqual(
            spoofed_vulnerable.json()["trace"]["customer_id_source"],
            "request-body",
        )

        spoof = self.client.post(
            "/api/labs/llm02/safe/chat",
            headers=self.headers,
            json={"customer_id": "C-2002", "message": self.message},
        )
        self.assertEqual(spoof.status_code, 422)
        self.assertEqual(len(self.llm.calls), 1)

    def test_safe_route_uses_verified_identity_and_minimized_context(self) -> None:
        response = self.client.post(
            "/api/labs/llm02/safe/chat",
            headers=self.headers,
            json={"message": self.message},
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["customer_id"], "C-2001")
        self.assertEqual(body["trace"]["query_authorized_for"], "C-2001")
        self.assertEqual(
            body["trace"]["authenticated_context"],
            {
                "subject": "customer-c2001",
                "customer_id": "C-2001",
                "verified_by": "server-side-bearer-token-map",
            },
        )
        self.assertEqual(
            body["trace"]["context_fields"],
            ["customer_id", "delivery_status", "estimated_arrival"],
        )
        self.assertEqual(body["trace"]["sensitive_fields_in_context"], [])
        self.assertEqual(body["trace"]["customer_ids_in_context"], ["C-2001"])
        self.assertFalse(body["trace"]["cross_customer_context"])
        self.assertEqual(
            body["trace"]["disclosure_control"],
            "server-field-allowlist-before-model",
        )
        self.assertNotIn("LAB-RECOVERY-C2001", self.llm.calls[0]["system"])
        self.assertNotIn("C-2002", self.llm.calls[0]["system"])


if __name__ == "__main__":
    unittest.main()
