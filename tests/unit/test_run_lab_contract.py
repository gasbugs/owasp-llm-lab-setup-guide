from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
MODULE_PATH = TOOLS / "run_lab_contract.py"
SPEC = importlib.util.spec_from_file_location("run_lab_contract", MODULE_PATH)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class MixedHostHarnessOutputTests(unittest.TestCase):
    def test_only_json_objects_are_projected_from_human_progress(self) -> None:
        text = "\n".join([
            "=== human progress ===",
            '{"event":"lab_case","case":"baseline-request"}',
            "  [R3] classification: pass",
            '["not", "an", "event"]',
            '{"event":"lab_case","case":"large-input-request"}',
        ])
        records = runner.parse_mixed_json_records(text)
        self.assertEqual(
            [record["case"] for record in records],
            ["baseline-request", "large-input-request"],
        )


if __name__ == "__main__":
    unittest.main()
