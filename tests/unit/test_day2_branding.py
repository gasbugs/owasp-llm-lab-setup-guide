"""Regression tests for the Day 2 CloudSecurityLab Bank brand contract."""
from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VULN_RAG_ROOT = ROOT / "docker" / "vuln-rag"


def load_day2_module():
    """Load vuln-rag's generic ``app`` package without leaking it to other tests."""
    saved_app_modules = {
        name: module
        for name, module in sys.modules.items()
        if name == "app" or name.startswith("app.")
    }
    for name in saved_app_modules:
        del sys.modules[name]

    sys.path.insert(0, str(VULN_RAG_ROOT))
    try:
        return importlib.import_module("app.scenarios.day2")
    finally:
        sys.path.remove(str(VULN_RAG_ROOT))
        for name in list(sys.modules):
            if name == "app" or name.startswith("app."):
                del sys.modules[name]
        sys.modules.update(saved_app_modules)


DAY2 = load_day2_module()


BRAND = "CloudSecurityLab Bank"
LEGACY_BRANDS = ("한빛", "Hanbit")


class Day2BrandingTest(unittest.TestCase):
    def test_api_scenario_metadata_uses_cloudsecuritylab_bank_brand(self) -> None:
        api_metadata = {
            "id": DAY2.scenario.id,
            "title": DAY2.scenario.title,
            "intro": DAY2.scenario.intro,
            "warning": DAY2.scenario.warning,
        }

        self.assertEqual(api_metadata["id"], "day2")
        self.assertEqual(
            api_metadata["title"],
            "CloudSecurityLab Bank 고객 서비스 (LLM02/LLM04)",
        )
        for field in ("title", "intro", "warning"):
            self.assertIn(BRAND, api_metadata[field], field)

        api_source = (VULN_RAG_ROOT / "app" / "main.py").read_text(encoding="utf-8")
        endpoint = api_source.split('@app.get("/api/scenarios")', 1)[1].split(
            '@app.get("/")', 1
        )[0]
        for field in ("id", "title", "intro", "warning"):
            self.assertIn(f'"{field}": scenario.{field}', endpoint)

    def test_system_prompt_uses_cloudsecuritylab_bank_brand(self) -> None:
        prompt = DAY2.build_system_prompt(context=[])

        self.assertIn("'CloudSecurityLab Bank 고객 서비스 AI'", prompt)
        for legacy in LEGACY_BRANDS:
            self.assertNotIn(legacy, prompt)

    def test_default_corpus_uses_cloudsecuritylab_bank_brand(self) -> None:
        docs = DAY2.list_docs()

        self.assertGreaterEqual(len(docs), 2)
        for doc in docs[:2]:
            self.assertIn(BRAND, doc)
            for legacy in LEGACY_BRANDS:
                self.assertNotIn(legacy, doc)

    def test_day2_source_does_not_restore_legacy_brand(self) -> None:
        source = (VULN_RAG_ROOT / "app" / "scenarios" / "day2.py").read_text(
            encoding="utf-8"
        )

        for legacy in LEGACY_BRANDS:
            self.assertNotIn(legacy, source)


if __name__ == "__main__":
    unittest.main()
