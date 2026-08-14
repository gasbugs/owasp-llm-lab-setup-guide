from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "security-monitoring"
sys.path.insert(0, str(EXAMPLE))

from policy_engine import evaluate, load_policy, text_identity  # noqa: E402


class SecurityMonitoringPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = load_policy(EXAMPLE / "policy.json")
        cls.tuning = load_policy(EXAMPLE / "policy-tuning-start.json")

    def event(self, **overrides):
        value = {
            "request_id": "unit-001",
            "stage": "input",
            "event_type": "user_prompt",
            "text": "public status request",
            "risk_score": 0.05,
            "detected_entities": [],
        }
        value.update(overrides)
        return value

    def test_normal_prompt_is_allowed(self) -> None:
        result = evaluate(self.event(), self.policy)
        self.assertEqual(result.application_decision, "allow")
        self.assertEqual(result.policy_rule, "default-allow")

    def test_injection_risk_is_blocked(self) -> None:
        result = evaluate(self.event(risk_score=0.96), self.policy)
        self.assertEqual(result.application_decision, "block")
        self.assertEqual(result.policy_rule, "prompt-injection-risk")

    def test_tuning_policy_exposes_miss_and_false_positive(self) -> None:
        missed = evaluate(self.event(risk_score=0.62), self.tuning)
        false_positive = evaluate(
            self.event(event_type="security_training_quote", risk_score=0.92),
            self.tuning,
        )
        self.assertEqual(missed.application_decision, "allow")
        self.assertEqual(false_positive.application_decision, "block")

    def test_safe_policy_fixes_miss_and_training_quote(self) -> None:
        detected = evaluate(self.event(risk_score=0.62), self.policy)
        training_quote = evaluate(
            self.event(event_type="security_training_quote", risk_score=0.92),
            self.policy,
        )
        self.assertEqual(detected.application_decision, "block")
        self.assertEqual(training_quote.application_decision, "allow")

    def test_anomaly_thresholds_are_explicit_policy(self) -> None:
        settings = self.policy["anomaly_detection"]
        self.assertEqual(settings["minimum_events"], 5)
        self.assertEqual(settings["block_ratio_threshold"], 0.5)
        self.assertEqual(settings["critical_rule_count_threshold"], 1)

    def test_sensitive_output_is_redacted(self) -> None:
        result = evaluate(
            self.event(stage="output", text="Contact ops@example.com"),
            self.policy,
        )
        self.assertEqual(result.application_decision, "redact")
        self.assertEqual(result.policy_rule, "sensitive-data")

    def test_cross_tenant_retrieval_is_blocked(self) -> None:
        result = evaluate(
            self.event(
                stage="retrieval",
                authenticated_tenant="acme",
                resource_tenant="beta",
            ),
            self.policy,
        )
        self.assertEqual(result.application_decision, "block")
        self.assertEqual(result.policy_rule, "rag-tenant-boundary")

    def test_dangerous_tool_requires_approval(self) -> None:
        blocked = evaluate(
            self.event(stage="tool", tool_name="delete_animal", approval_status="missing"),
            self.policy,
        )
        allowed = evaluate(
            self.event(stage="tool", tool_name="delete_animal", approval_status="approved"),
            self.policy,
        )
        self.assertEqual(blocked.application_decision, "block")
        self.assertEqual(allowed.application_decision, "allow")

    def test_request_limit_is_blocked(self) -> None:
        result = evaluate(
            self.event(stage="runtime", window_request_count=6),
            self.policy,
        )
        self.assertEqual(result.application_decision, "block")
        self.assertEqual(result.policy_rule, "request-rate-limit")

    def test_raw_text_is_hashed_and_redacted(self) -> None:
        raw = "Contact alice@example.com with DEMO_API_KEY=sk-demo-12345"
        digest, excerpt, entities = text_identity(raw)
        self.assertEqual(len(digest), 64)
        self.assertNotIn("alice@example.com", excerpt)
        self.assertNotIn("sk-demo-12345", excerpt)
        self.assertEqual(entities, ["DEMO_API_KEY", "EMAIL_ADDRESS"])


if __name__ == "__main__":
    unittest.main()
