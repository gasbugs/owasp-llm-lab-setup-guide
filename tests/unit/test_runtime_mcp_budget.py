"""Exercise the real SDK and count server-side calls, including a changed budget."""
import asyncio
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest


@unittest.skipUnless(importlib.util.find_spec("mcp"), "Run in the MCP image for SDK coverage")
class MCPBudgetTests(unittest.TestCase):
    def test_host_checks_each_attempt_before_calling_the_server(self):
        source = Path(__file__).resolve().parents[2] / "examples/runtime-security/mcp_budget_demo.py"
        for budget, expected in ((2, 2), (3, 3), (0, 0)):
            with self.subTest(budget=budget):
                spec = importlib.util.spec_from_file_location("budget_demo", source)
                demo = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(demo)
                demo.MAX_TOOL_CALLS = budget
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    asyncio.run(demo.main())
                result = json.loads(output.getvalue())
                loop = result["tool_loop"]
                self.assertEqual(loop["requested"], 3)
                self.assertEqual(loop["executed"], expected)
                self.assertEqual(loop["third_call_blocked"], budget < 3)
                self.assertEqual([d["tool_called"] for d in loop["decisions"]],
                                 [i < budget for i in range(3)])
                self.assertEqual(len(result["server_calls"]), expected + 3)
                self.assertTrue(result["normal"]["context_forwarded"])
                self.assertFalse(result["oversized_result"]["context_forwarded"])
                self.assertTrue(result["tool_timeout"]["blocked"])
                self.assertFalse(result["foreign_state"]["tool_called"])


if __name__ == "__main__":
    unittest.main()
