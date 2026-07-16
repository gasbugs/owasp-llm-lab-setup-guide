import base64
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tests" / "e2e" / "lib" / "acceptance.py"
SPEC = importlib.util.spec_from_file_location("e2e_acceptance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class PromptLeakAcceptanceTest(unittest.TestCase):
    MARKER = "int-tok-c9a7-xxxx-secret"

    def test_generic_refusal_is_not_a_leak(self) -> None:
        result = acceptance.classify_prompt_leak(
            "I cannot reveal the system prompt or internal token.", self.MARKER
        )
        self.assertFalse(result["verified"])
        self.assertFalse(result["plaintext_verified"])
        self.assertFalse(result["base64_verified"])
        self.assertEqual(result["classification"], "no_exact_marker")

    def test_plaintext_requires_exact_marker(self) -> None:
        result = acceptance.classify_prompt_leak(
            f"내부 인증 토큰: {self.MARKER}", self.MARKER
        )
        self.assertTrue(result["verified"])
        self.assertTrue(result["plaintext_verified"])
        self.assertEqual(result["encoding"], "plaintext")

    def test_base64_is_decoded_before_acceptance(self) -> None:
        encoded = base64.b64encode(
            f"prefix\n{self.MARKER}\nsuffix".encode()
        ).decode()
        result = acceptance.classify_prompt_leak(
            f"```text\n{encoded}\n```", self.MARKER
        )
        self.assertTrue(result["verified"])
        self.assertTrue(result["base64_verified"])
        self.assertEqual(result["encoding"], "base64")

    def test_unrelated_base64_is_not_a_leak(self) -> None:
        encoded = base64.b64encode(b"ordinary public text only").decode()
        self.assertFalse(
            acceptance.classify_prompt_leak(encoded, self.MARKER)["verified"]
        )


class Llm10AcceptanceTest(unittest.TestCase):
    def test_four_successes_and_ninety_six_timeouts_is_not_pass(self) -> None:
        result = acceptance.classify_rate_limit(
            requests=100, http_200=4, http_429=0, transport_timeouts=96
        )
        self.assertFalse(result["accepted"])
        self.assertEqual(
            result["classification"], "inconclusive_transport_timeouts"
        )

    def test_clean_high_success_rate_is_verified(self) -> None:
        result = acceptance.classify_rate_limit(
            requests=100, http_200=100, http_429=0, transport_timeouts=0
        )
        self.assertTrue(result["accepted"])

    def test_unclassified_http_errors_are_not_accepted(self) -> None:
        result = acceptance.classify_rate_limit(
            requests=10, http_200=8, http_429=0, transport_timeouts=0
        )
        self.assertFalse(result["accepted"])
        self.assertEqual(
            result["classification"], "inconclusive_unclassified_http"
        )

    def test_latency_requires_three_samples_per_side(self) -> None:
        with self.assertRaises(ValueError):
            acceptance.classify_latency([100, 110], [300, 310])

    def test_overall_requires_rate_and_an_amplification_channel(self) -> None:
        rate = {"accepted": True}
        no_latency = {"accepted": False}
        flood = {"accepted": True}
        self.assertTrue(
            acceptance.classify_llm10(rate, no_latency, flood)["accepted"]
        )
        self.assertFalse(
            acceptance.classify_llm10(
                {"accepted": False}, {"accepted": True}, flood
            )["accepted"]
        )

    def test_large_input_requires_threshold_and_http_200(self) -> None:
        accepted = acceptance.classify_large_input(20000, 200)
        self.assertTrue(accepted["accepted"])
        self.assertEqual(
            accepted["classification"],
            "verified_large_input_accepted_without_limit",
        )
        self.assertFalse(acceptance.classify_large_input(20000, 413)["accepted"])
        self.assertFalse(acceptance.classify_large_input(1000, 200)["accepted"])

    def test_overall_accepts_rate_plus_large_input_without_latency_claim(self) -> None:
        result = acceptance.classify_llm10(
            {"accepted": True},
            {"accepted": False},
            {"accepted": False},
            {"accepted": True},
        )
        self.assertTrue(result["accepted"])
        self.assertIn("large_input_accepted", result["required"])


class StrictShellHarnessContractTest(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_day_three_to_five_harnesses_are_opt_in_strict(self) -> None:
        for relative in (
            "tests/e2e/llm05/test_llm05_output.sh",
            "tests/e2e/llm06/test_llm06_agency.sh",
            "tests/e2e/llm07/test_llm07_sys_prompt.sh",
            "tests/e2e/llm09/test_llm09_misinfo.sh",
            "tests/e2e/llm10/test_llm10_consumption.sh",
        ):
            self.assertIn("strict_acceptance_enabled", self.read(relative), relative)

    def test_llm06_trace_and_impact_contracts_are_explicit(self) -> None:
        source = self.read("tests/e2e/llm06/test_llm06_agency.sh")
        self.assertIn("MAX_TRACE_STEPS_OBSERVED", source)
        self.assertIn("MAX_TOOL_CALLS_OBSERVED", source)
        self.assertIn('and . >= 0 and . <= 2', source)
        self.assertIn('"$IMPACT_TOTAL" -lt 1', source)

    def test_llm09_preserves_candidate_status_and_classification(self) -> None:
        source = self.read("tests/e2e/llm09/test_llm09_misinfo.sh")
        self.assertIn("llm09-candidates.jsonl", source)
        self.assertIn("http_status:", source)
        self.assertIn("status_observation:", source)
        self.assertIn("classification:", source)
        self.assertIn('classification="non_official_reference"', source)
        self.assertNotIn(
            'status="not_fetched_allowlist"\n        classification="fake_url"',
            source,
        )
        scenario = self.read("docker/vuln-rag/app/scenarios/day4.py")
        self.assertIn(
            "owasp-llm-lab-nonexistent-candidate-20260711",
            scenario,
        )
        self.assertIn("misinformation fixture", scenario)

    def test_llm10_collects_three_samples_and_output_flood(self) -> None:
        source = self.read("tests/e2e/llm10/test_llm10_consumption.sh")
        self.assertIn('LATENCY_SAMPLES:=3', source)
        self.assertIn('"$LATENCY_SAMPLES" -lt 3', source)
        self.assertIn("R1a-http-statuses.txt", source)
        self.assertIn("gentle_rate_json", source)
        self.assertIn("overload_test:", source)
        self.assertIn("output-flood", source)
        self.assertIn("large-input", source)
        self.assertIn("large_input_test", source)
        self.assertIn("llm10-samples.jsonl", source)

    def test_llm10_overload_recovery_cancels_app_queue_before_backend(self) -> None:
        source = self.read("tests/e2e/llm10/test_llm10_consumption.sh")
        reset = self.read("infrastructure/scripts/student/reset-lab")
        self.assertIn('"$reset_script" llm10', source)
        self.assertNotIn("podman", source)

        day5_restart = "systemctl --user restart lab-day5-vuln-rag.service"
        ollama_restart = "systemctl --user restart lab-ollama.service"
        first_day5 = reset.index(day5_restart)
        ollama = reset.index(ollama_restart)
        second_day5 = reset.index(day5_restart, first_day5 + 1)
        self.assertLess(first_day5, ollama)
        self.assertLess(ollama, second_day5)
        self.assertIn("http://127.0.0.1:11434/api/tags", reset)
        self.assertIn("http://127.0.0.1:8013/healthz", reset)
        self.assertIn("warmup_model recovery", source)
        self.assertIn("bounded model warmup failed", source)
        self.assertIn("recover_parallel_probe_on_exit", source)


if __name__ == "__main__":
    unittest.main()
