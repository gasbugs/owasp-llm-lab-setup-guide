from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "security-monitoring"
sys.path.insert(0, str(EXAMPLE))

from policy_engine import evaluate, load_policy, text_identity  # noqa: E402
from gpu_exporter import metrics  # noqa: E402


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

    def test_compose_defines_the_complete_observability_stack(self) -> None:
        compose = (EXAMPLE / "compose.yaml").read_text(encoding="utf-8")
        for service in (
            "gateway:",
            "otel-collector:",
            "prometheus:",
            "alertmanager:",
            "loki:",
            "tempo:",
            "grafana:",
        ):
            self.assertIn(service, compose)
        for binding in (
            "127.0.0.1:8014:8080",
            "127.0.0.1:3001:3000",
            "127.0.0.1:9090:9090",
            "127.0.0.1:9093:9093",
        ):
            self.assertIn(binding, compose)
        gpu = (EXAMPLE / "compose.gpu.yaml").read_text(encoding="utf-8")
        self.assertIn("gpu-exporter:", gpu)
        self.assertIn("nvidia.com/gpu=all", gpu)
        self.assertNotIn("privileged:", gpu)
        self.assertNotIn("SYS_ADMIN", gpu)

    def test_collector_routes_logs_and_traces_to_separate_backends(self) -> None:
        config = (EXAMPLE / "otel-collector.yaml").read_text(encoding="utf-8")
        self.assertIn("otlphttp/tempo", config)
        self.assertIn("otlphttp/loki", config)
        self.assertIn("traces:", config)
        self.assertIn("logs:", config)

    def test_installer_includes_cni_service_discovery(self) -> None:
        installer = (ROOT / "infrastructure" / "scripts" / "student" / "install-lab.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("golang-github-containernetworking-plugin-dnsname", installer)

    def test_gateway_owns_real_request_path_and_server_side_boundaries(self) -> None:
        source = (EXAMPLE / "app.py").read_text(encoding="utf-8")
        self.assertIn('@app.post("/api/chat")', source)
        self.assertIn("principal_from_authorization", source)
        self.assertIn("prompt_risk_score", source)
        self.assertIn("select_document", source)
        self.assertIn("requested_tool", source)
        self.assertIn("call_ollama", source)
        self.assertIn("llm.security.output_guardrail", source)
        self.assertIn("def request_trace(request_id:", source)
        self.assertNotIn("def trace(request_id:", source)

    def test_dashboard_correlates_metrics_logs_traces_and_gpu(self) -> None:
        dashboard = json.loads(
            (EXAMPLE / "grafana" / "dashboards" / "llm-security.json").read_text(
                encoding="utf-8"
            )
        )
        panel_types = {panel["type"] for panel in dashboard["panels"]}
        self.assertTrue({"stat", "gauge", "timeseries", "logs", "traces"}.issubset(panel_types))
        serialized = json.dumps(dashboard)
        self.assertIn("llm_gpu_utilization_percent", serialized)
        self.assertIn("llm-security-loki", serialized)
        self.assertIn("llm-security-tempo", serialized)

    @patch("gpu_exporter.subprocess.run")
    def test_gpu_exporter_maps_read_only_nvidia_query_to_metrics(self, run) -> None:
        run.return_value = SimpleNamespace(stdout="0, NVIDIA L4, 17, 2048, 23034, 51\n")
        output = metrics()
        self.assertIn('llm_gpu_utilization_percent{gpu="0",model="NVIDIA L4"} 17', output)
        self.assertIn('llm_gpu_memory_used_mib{gpu="0",model="NVIDIA L4"} 2048', output)
        command = run.call_args.args[0]
        self.assertEqual(command[0], "nvidia-smi")
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_alert_rules_cover_security_upstream_and_gpu_failures(self) -> None:
        rules = (EXAMPLE / "alert-rules.yml").read_text(encoding="utf-8")
        self.assertIn("LLMBlockingSpike", rules)
        self.assertIn("LLMGatewayUnavailable", rules)
        self.assertIn("OllamaUpstreamFailure", rules)
        self.assertIn("GPUMemoryPressure", rules)


if __name__ == "__main__":
    unittest.main()
