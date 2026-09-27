"""Incomplete generation must not look like a completed PyRIT evaluation."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


@unittest.skipUnless(importlib.util.find_spec("pyrit"), "Run in the PyRIT image for report coverage")
class PyRITReportTests(unittest.TestCase):
    def test_generation_completion_boundary(self):
        source = Path(__file__).resolve().parents[2] / "examples/day6/pyrit-guardrail/report.py"
        spec = importlib.util.spec_from_file_location("report", source)
        report = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(report)
        for reason in ("end_turn", "max_tokens", "length", "content_filter"):
            with self.subTest(reason=reason):
                response = {
                    "request_id": "synthetic-request", "application_decision": "allow",
                    "blocking_reason": None, "upstream_called": True, "reply": "partial",
                    "guardrail": {"stages": [{"stage": "bedrock_main", "decision": "allow",
                                              "stop_reason": reason}]},
                }
                messages = [SimpleNamespace(get_value=lambda: "synthetic prompt"),
                            SimpleNamespace(get_value=lambda: json.dumps(response),
                                            get_piece=lambda: SimpleNamespace(timestamp=1))]
                memory = SimpleNamespace(get_conversation_messages=lambda **kw: messages)
                result = SimpleNamespace(get_all_conversation_ids=lambda: ["conversation"],
                                         executed_turns=1, outcome=SimpleNamespace(value="failure"),
                                         last_score=SimpleNamespace(get_value=lambda: False))
                output = io.StringIO()
                with patch.object(report.CentralMemory, "get_memory_instance", return_value=memory), contextlib.redirect_stdout(output):
                    if reason == "end_turn":
                        report.print_result(result)
                    else:
                        with self.assertRaises(SystemExit) as raised:
                            report.print_result(result)
                        self.assertEqual(raised.exception.code, 1)
                observed = json.loads(output.getvalue())
                self.assertEqual(observed["turns"][0]["generation_stop_reason"], reason)
                if reason == "end_turn":
                    self.assertEqual(observed["pyrit_outcome"], "failure")
                else:
                    self.assertEqual(observed["course_verdict"], "ERR")
                    self.assertEqual(observed["error_type"], "IncompleteModelResponse")


if __name__ == "__main__":
    unittest.main()
