"""The CI matrix reuses existing publishers and never opts into AWS."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("practice_ci_pair", ROOT / "tests/e2e/run_practice_ci_pair.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class PracticeCiPairTests(unittest.TestCase):
    def test_starter_and_solution_use_existing_scripts_and_fixtures(self):
        for practice in runner.PRACTICES:
            with self.subTest(practice=practice):
                starter, solution = runner.commands(practice, Path("/tmp/fresh-evidence"), sys.executable)
                self.assertIn("--starter", starter)
                self.assertNotIn("--starter", solution)
                self.assertNotEqual(starter[-1], solution[-1])
                for command in (starter, solution):
                    self.assertTrue((ROOT / command[1]).is_file())
                    self.assertFalse(any(arg.startswith("--aws") for arg in command))
                    for arg in command[2:]:
                        if arg.startswith(("tests/e2e/fixtures/", "llm-security-control-plane/guided-labs/")):
                            self.assertTrue((ROOT / arg).is_file(), arg)
                if practice in ("P17", "P19"):
                    self.assertIn("guided-labs/", starter[2])
                    self.assertIn("fixtures/", solution[2])


if __name__ == "__main__":
    unittest.main()
