"""Deterministic reset contract for the intentionally stateful agent lab."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "docker" / "vuln-agent"))

from app import tools  # noqa: E402


class AgentResetTest(unittest.TestCase):
    def tearDown(self) -> None:
        tools.reset_lab_state()

    def test_reset_restores_deleted_animal_and_clears_log(self) -> None:
        self.assertEqual(tools.delete_animal("g-003"), {"deleted": "g-003"})
        self.assertNotIn("g-003", tools.ANIMALS)
        self.assertEqual(tools.DELETED_LOG, ["g-003"])

        result = tools.reset_lab_state()

        self.assertTrue(result["ok"])
        self.assertIn("g-003", tools.ANIMALS)
        self.assertEqual(tools.DELETED_LOG, [])


if __name__ == "__main__":
    unittest.main()
