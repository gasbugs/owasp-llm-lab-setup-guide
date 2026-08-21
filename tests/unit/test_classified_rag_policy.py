from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docker" / "vuln-rag" / "app" / "classified_rag.py"
SPEC = importlib.util.spec_from_file_location("classified_rag_policy", SOURCE)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ClassifiedRagPolicyTests(unittest.TestCase):
    def test_public_reader_can_select_only_public_store(self) -> None:
        principal = MODULE.authenticate("Bearer rag-public-reader-token")
        result = MODULE.retrieve_authorized(
            principal=principal,
            classification="public",
        )
        self.assertEqual(result["selected_rag"], "public-rag")
        self.assertEqual(result["authenticated_subject"], "public-reader")

        with self.assertRaisesRegex(
            MODULE.RagAuthorizationError,
            "classification-not-authorized",
        ):
            MODULE.retrieve_authorized(
                principal=principal,
                classification="restricted",
            )

    def test_support_agent_can_select_restricted_store(self) -> None:
        principal = MODULE.authenticate("Bearer rag-support-agent-token")
        result = MODULE.retrieve_authorized(
            principal=principal,
            classification="restricted",
        )
        self.assertEqual(result["selected_rag"], "restricted-rag")
        self.assertEqual(
            result["handling_policy"],
            "allow-exact-after-application-authorization",
        )
        self.assertTrue(result["documents"][0]["exact_value_required"])

    def test_request_body_cannot_supply_an_identity(self) -> None:
        with self.assertRaises(MODULE.RagAuthenticationError):
            MODULE.authenticate(None)


if __name__ == "__main__":
    unittest.main()
