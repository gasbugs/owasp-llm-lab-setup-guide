"""Contract checks for the learner-facing bounded LLM10 probe."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "examples/llm10/bounded_concurrency_probe.py"


class Llm10BoundedConcurrencyProbeTest(unittest.TestCase):
    def test_probe_has_hard_request_and_parallel_bounds(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("1 <= args.requests <= 20", text)
        self.assertIn("1 <= args.parallel <= 4", text)
        self.assertIn('"statuses": statuses', text)
        self.assertIn('"http_429": statuses.count(429)', text)
        self.assertIn('"transport_errors": statuses.count(0)', text)

    def test_request_classification_preserves_http_and_transport(self) -> None:
        spec = importlib.util.spec_from_file_location("llm10_probe", SOURCE)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        self.assertTrue(callable(module.request_once))


if __name__ == "__main__":
    unittest.main()
