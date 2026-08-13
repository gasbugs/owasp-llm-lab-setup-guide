"""The publisher toggle changes only the two adjacent learner calls."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "toggle_secure_coding_lab",
    ROOT / "tools/toggle_secure_coding_lab.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SecureCodingToggleTest(unittest.TestCase):
    def test_python_pair_round_trip(self) -> None:
        original = (
            "# NODEGOAT-LAB: LLM01\n"
            "decision = vulnerable()  # VULNERABLE-ACTIVE\n"
            "# decision = safe()  # SAFE-ENABLE\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "main.py"
            path.write_text(original, encoding="utf-8")
            with patch.dict(MODULE.FILES, {"LLM01": path}, clear=True):
                MODULE.toggle("LLM01", "safe")
                safe = path.read_text(encoding="utf-8")
                self.assertIn("# decision = vulnerable()", safe)
                self.assertIn("\ndecision = safe()", safe)
                MODULE.toggle("LLM01", "vulnerable")
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_javascript_pair_round_trip(self) -> None:
        original = (
            "// NODEGOAT-LAB: LLM05\n"
            "renderVulnerable(); // VULNERABLE-ACTIVE\n"
            "// renderSafe(); // SAFE-ENABLE\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "index.html"
            path.write_text(original, encoding="utf-8")
            with patch.dict(MODULE.FILES, {"LLM05": path}, clear=True):
                MODULE.toggle("LLM05", "safe")
                safe = path.read_text(encoding="utf-8")
                self.assertIn("// renderVulnerable()", safe)
                self.assertIn("\nrenderSafe()", safe)
                MODULE.toggle("LLM05", "vulnerable")
            self.assertEqual(path.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
