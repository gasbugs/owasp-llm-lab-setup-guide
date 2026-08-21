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
        digest, excerpt, entities = text_identity(
            raw,
            "unit-test-hmac-key",
            self.policy["sensitive_data"]["patterns"],
        )
        self.assertEqual(len(digest), 64)
        self.assertNotIn("alice@example.com", excerpt)
        self.assertNotIn("sk-demo-12345", excerpt)
        self.assertEqual(entities, ["DEMO_API_KEY", "EMAIL_ADDRESS"])

    def test_prompt_identity_is_keyed_and_policy_regex_is_canonical(self) -> None:
        first = text_identity("repeatable prompt", "key-a")[0]
        second = text_identity("repeatable prompt", "key-b")[0]
        self.assertNotEqual(first, second)
        self.assertIn("DEMO_API_KEY", self.policy["sensitive_data"]["patterns"])

    def test_compose_defines_the_complete_observability_stack(self) -> None:
        compose = (EXAMPLE / "compose.yaml").read_text(encoding="utf-8")
        for service in (
            "gateway:",
            "retrieval:",
            "alloy:",
            "prometheus:",
            "alertmanager:",
            "alert-webhook:",
            "loki:",
            "tempo:",
            "grafana:",
        ):
            self.assertIn(service, compose)
        for binding in (
            "0.0.0.0:8014:8080",
            "0.0.0.0:8015:8081",
            "0.0.0.0:3001:3000",
            "0.0.0.0:9090:9090",
            "0.0.0.0:9093:9093",
            "0.0.0.0:12345:12345",
        ):
            self.assertIn(binding, compose)
        gpu = (EXAMPLE / "compose.gpu.yaml").read_text(encoding="utf-8")
        self.assertIn("gpu-exporter:", gpu)
        self.assertIn("nvidia.com/gpu=all", gpu)
        self.assertIn("0.0.0.0:9400:9400", gpu)
        self.assertNotIn("privileged:", gpu)
        self.assertNotIn("SYS_ADMIN", gpu)

    def test_compose_uses_the_verified_single_bridge_podman_topology(self) -> None:
        compose = (EXAMPLE / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn("name: llm-security-observability", compose)
        self.assertNotIn("name: llm-security-telemetry", compose)
        self.assertNotIn("name: llm-security-application", compose)
        self.assertGreaterEqual(compose.count("networks: [observability]"), 9)

    def test_grafana_does_not_download_plugins_at_startup(self) -> None:
        compose = (EXAMPLE / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn('GF_ANALYTICS_CHECK_FOR_UPDATES: "false"', compose)
        self.assertIn('GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES: "false"', compose)
        self.assertIn('GF_PLUGINS_PREINSTALL_DISABLED: "true"', compose)
        self.assertIn('GF_PLUGINS_PREINSTALL_AUTO_UPDATE: "false"', compose)

    def test_alloy_collects_container_logs_and_routes_otlp_signals(self) -> None:
        config = (EXAMPLE / "alloy" / "config.alloy").read_text(encoding="utf-8")
        self.assertIn('discovery.docker "podman"', config)
        self.assertIn("day6-presidio-api", config)
        self.assertIn("day6-nemo-guardrails-api", config)
        self.assertIn("day6-guardrail-ui", config)
        self.assertIn('action        = "keep"', config)
        self.assertIn('loki.source.docker "podman"', config)
        self.assertIn('targets       = discovery.relabel.container_logs.output', config)
        self.assertIn("DEMO_API_KEY", config)
        self.assertIn("[REDACTED-EMAIL]", config)
        self.assertNotIn('target_label  = "container_id"', config)
        self.assertIn('otelcol.receiver.otlp "application"', config)
        self.assertIn('otelcol.exporter.otlphttp "loki"', config)
        self.assertIn('otelcol.exporter.otlphttp "tempo"', config)
        self.assertIn("sending_queue", config)
        self.assertIn("retry_on_failure", config)

    def test_log_probe_waits_for_discovery_before_emitting_secret(self) -> None:
        source = (EXAMPLE / "log_redaction_probe.py").read_text(encoding="utf-8")
        self.assertLess(source.index("time.sleep(6)"), source.index("print("))
        self.assertLess(source.index("print("), source.index("time.sleep(8)"))
        self.assertIn(
            "log_redaction_probe.py",
            (EXAMPLE / "Containerfile").read_text(encoding="utf-8"),
        )

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
        self.assertIn("call_retrieval", source)
        self.assertIn("requested_tool", source)
        self.assertIn("call_ollama", source)
        self.assertIn("llm.security.output_guardrail", source)
        self.assertIn('"input_hmac_sha256": record["input_hmac_sha256"]', source)
        self.assertIn("def request_trace(", source)
        self.assertNotIn("def trace(request_id:", source)
        self.assertIn("FastAPIInstrumentor.instrument_app", source)
        self.assertIn("HTTPXClientInstrumentor().instrument", source)
        self.assertIn("llm_chat_request_duration_seconds", source)
        self.assertIn("llm_gen_ai_tokens_total", source)
        self.assertIn("def initialize_bounded_metric_series()", source)
        self.assertIn('("block", "input")', source)
        self.assertIn("TELEMETRY_INGEST_TOKEN", source)
        self.assertIn("llm_guardrail_decisions_total", source)
        self.assertIn("llm_guardrail_duration_seconds", source)
        self.assertIn("llm_guardrail_model_calls_total", source)
        self.assertIn("def bounded_guardrail_label", source)
        self.assertIn('else "other"', source)

    def test_retrieval_service_is_instrumented_and_does_not_log_queries(self) -> None:
        source = (EXAMPLE / "retrieval_service.py").read_text(encoding="utf-8")
        self.assertIn('"service.name": "llm-security-retrieval"', source)
        self.assertIn("FastAPIInstrumentor.instrument_app", source)
        self.assertIn('"raw_query_stored": False', source)
        self.assertIn("x_service_token", source)

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
        self.assertIn("llm-security-prometheus", serialized)
        self.assertNotIn("llm-security-mimir", serialized)
        self.assertIn("llm-security-loki", serialized)
        self.assertIn("llm-security-tempo", serialized)
        self.assertIn("All container stdout and stderr", serialized)
        self.assertIn("Telemetry loss and exporter queue pressure", serialized)
        self.assertIn("Presidio and NeMo guardrail decisions", serialized)
        self.assertIn("llm_guardrail_decisions_total", serialized)
        self.assertIn("otelcol_exporter_queue_size", serialized)
        self.assertEqual(dashboard["refresh"], "5s")

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
        self.assertIn("Module08LearnerDrill", rules)
        self.assertIn("expr: vector(0)", rules)
        self.assertIn('increase(llm_chat_requests_total{outcome="block"}[5m])', rules)
        self.assertIn("LLMGatewayUnavailable", rules)
        self.assertIn("LLMObservabilityPipelineUnavailable", rules)
        self.assertIn("AlertDeliveryStalled", rules)
        self.assertNotIn("MimirRemoteWriteFailure", rules)
        self.assertIn("TelemetryDataDropped", rules)
        self.assertIn("AlloyExporterQueuePressure", rules)
        self.assertIn("OllamaUpstreamFailure", rules)
        self.assertIn("GPUMemoryPressure", rules)

    def test_alertmanager_delivers_to_lab_webhook(self) -> None:
        config = (EXAMPLE / "alertmanager.yml").read_text(encoding="utf-8")
        self.assertIn("http://alert-webhook:8099/api/alerts", config)
        self.assertIn("send_resolved: true", config)

    def test_prometheus_is_metric_store_and_remote_write_receiver(self) -> None:
        compose = (EXAMPLE / "compose.yaml").read_text(encoding="utf-8")
        config = (EXAMPLE / "prometheus.yml").read_text(encoding="utf-8")
        self.assertIn("--web.enable-remote-write-receiver", compose)
        self.assertNotIn("remote_write:", config)
        self.assertNotIn("mimir", config.lower())
        for job in ("alloy", "loki", "tempo", "alertmanager", "alert-webhook", "grafana"):
            self.assertIn(f"job_name: {job}", config)

    def test_gpu_target_name_matches_publisher_e2e(self) -> None:
        prometheus = (EXAMPLE / "prometheus.yml").read_text(encoding="utf-8")
        e2e = (
            ROOT / "tests" / "e2e" / "security-monitoring" / "test_security_monitoring.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("job_name: nvidia-gpu", prometheus)
        self.assertIn('.labels.job == "nvidia-gpu"', e2e)

    def test_tempo_generates_span_metrics_and_service_graphs(self) -> None:
        compose = (EXAMPLE / "compose.yaml").read_text(encoding="utf-8")
        config = (EXAMPLE / "tempo.yaml").read_text(encoding="utf-8")
        self.assertIn("docker.io/grafana/tempo:3.0.2", compose)
        self.assertIn('command: ["-target=all",', compose)
        self.assertIn("service-graphs", config)
        self.assertIn("span-metrics", config)
        self.assertIn("http://prometheus:9090/api/v1/write", config)
        self.assertIn("remote_write_add_org_id_header: false", config)
        self.assertNotIn("ingester:", config)
        self.assertNotIn("compactor:", config)


if __name__ == "__main__":
    unittest.main()
