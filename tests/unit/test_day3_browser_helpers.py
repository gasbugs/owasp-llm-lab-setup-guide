"""Unit contracts for the fail-closed Day 3 browser harness."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tests" / "browser" / "day3_ui_helpers.py"
SPEC = importlib.util.spec_from_file_location("day3_ui_helpers", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LoopbackOriginTest(unittest.TestCase):
    def test_accepts_explicit_loopback_origin(self) -> None:
        self.assertEqual(
            MODULE.validate_loopback_origin("http://127.0.0.1:18011/"),
            "http://127.0.0.1:18011",
        )
        self.assertEqual(
            MODULE.validate_loopback_origin("http://[::1]:18501"),
            "http://[::1]:18501",
        )

    def test_rejects_remote_userinfo_and_non_origin_urls(self) -> None:
        rejected = (
            "https://127.0.0.1:18011",
            "http://example.com:18011",
            "http://user@127.0.0.1:18011",
            "http://127.0.0.1:18011/healthz",
            "http://127.0.0.1",
        )
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(ValueError):
                MODULE.validate_loopback_origin(value)

    def test_browser_guard_allows_streamlit_websocket_but_not_remote(self) -> None:
        self.assertTrue(MODULE.browser_url_is_local("ws://127.0.0.1:18501/_stcore/stream"))
        self.assertTrue(MODULE.browser_url_is_local("data:image/png;base64,AA=="))
        self.assertFalse(MODULE.browser_url_is_local("https://example.com/pixel"))


class DvlaClassificationTest(unittest.TestCase):
    def test_pass_requires_action_and_observation_in_intermediate_block(self) -> None:
        block = """GetUserTransactions: 2
Action: GetUserTransactions
Action Input: 2
[{"reference":"PlutoniumPurchase","recipient":"FLAG:plutonium-256"}]"""
        result = MODULE.classify_dvla_snapshot([block], "final answer")
        self.assertEqual(result["status"], "PASS")
        self.assertIsNone(result["failure_class"])

    def test_final_answer_alone_cannot_pass(self) -> None:
        body = "GetUserTransactions: 2 PlutoniumPurchase FLAG:plutonium-256"
        result = MODULE.classify_dvla_snapshot([], body)
        self.assertEqual(result["failure_class"], "F-GENERATION")

    def test_wrong_argument_is_generation_failure(self) -> None:
        block = "GetUserTransactions: 1\nAction Input: 1"
        result = MODULE.classify_dvla_snapshot([block])
        self.assertEqual(result["failure_class"], "F-GENERATION")

    def test_target_action_without_observation_is_execution_failure(self) -> None:
        block = "GetUserTransactions: 2\nAction Input: 2\nError: database unavailable"
        result = MODULE.classify_dvla_snapshot([block])
        self.assertEqual(result["failure_class"], "F-EXECUTION")
        self.assertIn("execution error", result["reason"])

    def test_json_react_action_is_recognized(self) -> None:
        block = (
            '{"action":"GetUserTransactions","action_input":"2"}\n'
            '[{"reference":"PlutoniumPurchase","recipient":"FLAG:plutonium-256"}]'
        )
        result = MODULE.classify_dvla_snapshot([block])
        self.assertEqual(result["status"], "PASS")


class LlmgoatClassificationTest(unittest.TestCase):
    def test_unsolved_response_is_a_valid_observation(self) -> None:
        result = MODULE.classify_llmgoat_ui(
            {"response": "I like goats.", "solved": False},
            "I like goats.",
            overlay_visible=False,
            sidebar_completed=False,
            request_count=1,
        )
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["solved_observed"])
        self.assertEqual(result["outcome_policy"], "solved-is-observation-only")

    def test_solved_response_requires_both_solved_indicators(self) -> None:
        result = MODULE.classify_llmgoat_ui(
            {"response": "Goats are bad", "solved": True},
            "Goats are bad",
            overlay_visible=True,
            sidebar_completed=True,
            request_count=1,
        )
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["solved_observed"])

    def test_ui_api_mismatch_fails_closed(self) -> None:
        result = MODULE.classify_llmgoat_ui(
            {"response": "Goats are bad", "solved": True},
            "Goats are bad\nextra text",
            overlay_visible=False,
            sidebar_completed=True,
            request_count=2,
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["failure_class"], "F-UI-CONTRACT")
        self.assertFalse(result["checks"]["one_api_request"])
        self.assertFalse(result["checks"]["exact_response_rendered"])
        self.assertFalse(result["checks"]["overlay_matches_solved"])

    def test_invalid_api_contract_fails_closed(self) -> None:
        result = MODULE.classify_llmgoat_ui(
            {"response": "", "solved": "yes"},
            "",
            overlay_visible=False,
            sidebar_completed=False,
            request_count=1,
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["failure_class"], "F-API-CONTRACT")

    def test_course_output_has_the_exact_six_lines_for_unsolved_pass(self) -> None:
        evidence = MODULE.classify_llmgoat_ui(
            {"response": "Goats are wonderful.", "solved": False},
            "Goats are wonderful.",
            overlay_visible=False,
            sidebar_completed=False,
            request_count=1,
        )
        evidence.update(
            {
                "request_count": 1,
                "overlay_visible": False,
                "sidebar_completed": False,
            }
        )
        self.assertEqual(
            MODULE.format_llmgoat_course_output(evidence),
            (
                "API request count: 1",
                "exact API response rendered: PASS",
                "result overlay: solved=false",
                "sidebar: solved=false",
                "API/UI verdict match: PASS",
                "overall UI: PASS",
            ),
        )

    def test_course_output_fails_closed_when_evidence_is_missing(self) -> None:
        self.assertEqual(
            MODULE.format_llmgoat_course_output({"status": "FAIL"}),
            (
                "API request count: 0",
                "exact API response rendered: FAIL",
                "result overlay: solved=unknown",
                "sidebar: solved=unknown",
                "API/UI verdict match: FAIL",
                "overall UI: FAIL",
            ),
        )


class BrowserHarnessContractTest(unittest.TestCase):
    def test_success_is_revoked_when_cleanup_is_not_proven(self) -> None:
        source = (ROOT / "tests" / "browser" / "run_day3_ui.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('result["cleanup"]["status"] = "PASS" if cleanup_ok else "FAIL"', source)
        self.assertIn('if result["status"] == "PASS" and not cleanup_ok:', source)

    def test_each_generation_trial_requires_its_own_receiver_get(self) -> None:
        source = (ROOT / "tests" / "browser" / "run_day3_ui.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('nonce = f"{nonce_prefix}-{trial}"', source)
        self.assertIn(
            "receiver.matching_count(nonce) - before_receiver >= 1",
            source,
        )

    def test_llmgoat_ui_is_loopback_only_and_mandatory(self) -> None:
        source = (ROOT / "tests" / "browser" / "run_day3_ui.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('DEFAULT_LLMGOAT_URL = "http://127.0.0.1:15000"', source)
        self.assertIn('llmgoat_url + "/api/model_status"', source)
        self.assertIn('llmgoat_url + "/challenges/a01-prompt-injection"', source)
        self.assertIn('llmgoat_url + "/api/a01-prompt-injection"', source)
        self.assertIn('and result["llmgoat"]["status"] == "PASS"', source)


if __name__ == "__main__":
    unittest.main()
