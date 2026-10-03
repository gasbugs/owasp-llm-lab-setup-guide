"""Exercise the production chat handler with controlled service boundaries."""
import ast
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

SOURCE = Path(__file__).resolve().parents[2] / "examples/guardrails/presidio/server.py"


class EmailSwitchTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        tree = ast.parse(SOURCE.read_text())
        handler = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "chat")
        handler.decorator_list = []
        self.scan = {"entity_types": ["EMAIL_ADDRESS"], "sanitized_text": "Email <EMAIL_ADDRESS>.", "valid": False}
        self.upstream = AsyncMock(return_value=("Safe response", {"decision": "allow", "upstream_called": True}, ["nemo_input", "bedrock_main", "nemo_output"]))
        self.scope = {
            "ChatRequest": SimpleNamespace, "time": time, "uuid": uuid,
            "GUARD_MODE": "enforce", "GUARD_ENGINE": "presidio", "BLOCK_EMAIL_INPUT": False,
            "CORE": SimpleNamespace(settings=SimpleNamespace(input_enabled=True, output_enabled=False), scan_input=Mock(return_value=self.scan)),
            "NEMO_GUARD_URL": "http://nemo:8013", "call_model_path": self.upstream,
            "scan_metadata": lambda result: dict(result), "base_guardrail": lambda **kw: kw,
            "emit": Mock(),
        }
        exec(compile(ast.Module(body=[handler], type_ignores=[]), str(SOURCE), "exec"), self.scope)

    async def invoke(self):
        return await self.scope["chat"](SimpleNamespace(message="Email analyst@example.com."))

    async def test_default_redacts_before_upstream(self):
        result = await self.invoke()
        self.assertEqual(result["guardrail"]["decision"], "redact")
        self.upstream.assert_awaited_once_with("Email <EMAIL_ADDRESS>.")

    async def test_switch_blocks_even_without_upstream(self):
        self.scope.update(BLOCK_EMAIL_INPUT=True, NEMO_GUARD_URL="")
        guard = (await self.invoke())["guardrail"]
        self.assertEqual(guard["decision"], "block")
        self.assertEqual(guard["blocking_reason"], "input:prohibited:EMAIL_ADDRESS")
        self.assertEqual(guard["stage_order"], ["presidio_input"])
        self.assertFalse(guard["upstream_called"])
        self.assertIsNone(guard["inner_guardrail"])
        self.upstream.assert_not_awaited()

    async def test_clean_input_continues_with_switch_on(self):
        self.scope["BLOCK_EMAIL_INPUT"] = True
        self.scan.update(entity_types=[], valid=True, sanitized_text="Clean input")
        self.assertEqual((await self.invoke())["guardrail"]["decision"], "allow")
        self.upstream.assert_awaited_once_with("Clean input")

    async def test_audit_does_not_enforce_switch(self):
        self.scope.update(BLOCK_EMAIL_INPUT=True, GUARD_MODE="audit")
        self.assertEqual((await self.invoke())["guardrail"]["decision"], "allow")
        self.upstream.assert_awaited_once_with("Email analyst@example.com.")

    async def test_analyzer_failure_never_calls_upstream(self):
        self.scope["BLOCK_EMAIL_INPUT"] = True
        self.scope["CORE"].scan_input.side_effect = RuntimeError("scanner unavailable")
        guard = (await self.invoke())["guardrail"]
        self.assertEqual(guard["blocking_reason"], "analyzer_error:RuntimeError")
        self.assertFalse(guard["upstream_called"])
        self.upstream.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
