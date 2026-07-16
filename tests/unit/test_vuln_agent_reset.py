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

    def test_read_state_is_sorted_and_does_not_expose_mutable_globals(self) -> None:
        initial = tools.read_lab_state()

        self.assertEqual(
            [animal["animal_id"] for animal in initial["animals"]],
            ["g-001", "g-002", "g-003"],
        )
        self.assertEqual(initial["deleted_log"], [])

        self.assertEqual(tools.delete_animal("g-003"), {"deleted": "g-003"})
        changed = tools.read_lab_state()
        self.assertEqual(
            [animal["animal_id"] for animal in changed["animals"]],
            ["g-001", "g-002"],
        )
        self.assertEqual(changed["deleted_log"], ["g-003"])

        changed["animals"][0]["name"] = "mutated snapshot"
        changed["deleted_log"].append("fake")
        fresh = tools.read_lab_state()
        self.assertEqual(fresh["animals"][0]["name"], "황금")
        self.assertEqual(fresh["deleted_log"], ["g-003"])


if __name__ == "__main__":
    unittest.main()
