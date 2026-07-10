"""Regression tests for the vulnerable agent's tool-call response parser."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "docker" / "vuln-agent" / "app" / "tool_call_parser.py"
SPEC = importlib.util.spec_from_file_location("tool_call_parser", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
extract_tool_call = MODULE.extract_tool_call


class ExtractToolCallTest(unittest.TestCase):
    def test_extracts_nested_args(self) -> None:
        response = '{"tool":"debug_sql","args":{"query":"SELECT * FROM users"}}'

        self.assertEqual(
            extract_tool_call(response),
            {"tool": "debug_sql", "args": {"query": "SELECT * FROM users"}},
        )

    def test_extracts_json_from_markdown_and_prose(self) -> None:
        response = (
            "도구를 호출하겠습니다.\n```json\n"
            '{"tool":"send_message","args":{"to_user":"vet","body":"help"}}\n'
            "```"
        )

        self.assertEqual(extract_tool_call(response)["tool"], "send_message")

    def test_skips_irrelevant_object_before_tool_call(self) -> None:
        response = (
            '{"status":"thinking"}\n'
            '{"tool":"get_vet_phone","args":{"vet_id":"vet"}}'
        )

        self.assertEqual(extract_tool_call(response)["tool"], "get_vet_phone")

    def test_defaults_missing_args_to_empty_object(self) -> None:
        self.assertEqual(
            extract_tool_call('{"tool":"list_animals"}'),
            {"tool": "list_animals", "args": {}},
        )

    def test_rejects_non_object_args_and_malformed_json(self) -> None:
        self.assertIsNone(extract_tool_call('{"tool":"debug_sql","args":"query"}'))
        self.assertIsNone(extract_tool_call('{"tool":"debug_sql","args":{'))


if __name__ == "__main__":
    unittest.main()
