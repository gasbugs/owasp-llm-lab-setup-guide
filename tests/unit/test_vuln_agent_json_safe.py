"""Regression tests for model text that is not directly UTF-8 encodable."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "docker" / "vuln-agent" / "app" / "json_safe.py"
SPEC = importlib.util.spec_from_file_location("json_safe", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
replace_unpaired_surrogates = MODULE.replace_unpaired_surrogates


class JsonSafeModelOutputTest(unittest.TestCase):
    def test_replaces_surrogates_recursively_and_encodes_as_utf8(self) -> None:
        unsafe = {
            "reply": "broken \udd0d text",
            "trace": [{"llm": "prefix \ud800 suffix"}],
            "normal": "정상 한글 🐐",
        }

        safe = replace_unpaired_surrogates(unsafe)

        self.assertEqual(safe["reply"], "broken \ufffd text")
        self.assertEqual(safe["trace"][0]["llm"], "prefix \ufffd suffix")
        self.assertEqual(safe["normal"], "정상 한글 🐐")
        json.dumps(safe, ensure_ascii=False).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
