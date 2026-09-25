"""Publisher diagnostic operation limits; no AWS or network calls."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
with patch.object(sys, "path", [str(ROOT / "tests/e2e"),
        str(ROOT / "llm-security-control-plane/guided-bedrock-gateway"), *sys.path]):
    import diagnose_p03_preparation as module
    from p03_ledger import LedgerError


class DiagnosticTests(unittest.TestCase):
    def test_default_allows_audit_and_ingestion_only(self):
        for name in module.READ_OPERATIONS | {"ListObjectsV2", "GetObject", "StartIngestionJob", "GetIngestionJob"}:
            module.guard_operation(name)

    def test_source_creation_requires_explicit_option(self):
        with self.assertRaises(LedgerError):
            module.guard_operation("PutObject")
        module.guard_operation("PutObject", create_source=True)

    def test_search_requires_explicit_option(self):
        with self.assertRaises(LedgerError):
            module.guard_operation("Retrieve")
        module.guard_operation("Retrieve", retrieve=True)

    def test_options_do_not_authorize_resource_changes_or_model_chat(self):
        for name in ("DeleteObject", "DeleteBucket", "CreateKnowledgeBase", "UpdateDataSource",
                     "CreateRole", "PutRolePolicy", "InvokeModel", "Converse", "RetrieveAndGenerate"):
            with self.subTest(operation=name), self.assertRaises(LedgerError):
                module.guard_operation(name, create_source=True, retrieve=True)


if __name__ == "__main__":
    unittest.main()
