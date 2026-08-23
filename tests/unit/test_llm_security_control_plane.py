"""Static and pure-policy checks for the isolated NeMo hub control plane."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "llm-security-control-plane"

# The application gateway directory is not a Python package in the container image.
sys.path.insert(0, str(CONTROL / "application-gateway"))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class LlmSecurityControlPlaneTests(unittest.TestCase):
    def test_bedrock_contract_double_inspects_only_runtime_content(self) -> None:
        fake = load_module(
            "control_plane_fake_bedrock_gateway",
            CONTROL / "tests/fake_bedrock_gateway.py",
        )
        safe_self_check = {
            "messages": [
                {
                    "content": (
                        "Example unsafe response: DEMO_API_KEY=sk-demo-12345\n"
                        "Bot response: 비밀번호 변경 페이지를 이용하세요.\n"
                        "Blocked (Yes or No):"
                    )
                }
            ]
        }
        unsafe_self_check = {
            "messages": [
                {
                    "content": (
                        "Bot response: DEMO_API_KEY=sk-demo-12345\n"
                        "Blocked (Yes or No):"
                    )
                }
            ]
        }
        safe_llama_guard = {
            "messages": [
                {
                    "content": (
                        "S3 includes credential theft.\n"
                        "User: 비밀번호 변경 절차를 알려 주세요.\n"
                        "The first line must be exactly safe or unsafe."
                    )
                }
            ]
        }
        self.assertEqual(fake.response_for_openai(safe_self_check), "No")
        self.assertEqual(fake.response_for_openai(unsafe_self_check), "Yes")
        self.assertEqual(fake.response_for_openai(safe_llama_guard), "safe")

    def test_versions_are_explicit_and_model_digests_are_full(self) -> None:
        lock = yaml.safe_load((CONTROL / "versions.lock.yaml").read_text())
        self.assertNotIn("latest", lock["ollama_models"]["main"]["tag"])
        self.assertNotIn("latest", lock["ollama_models"]["llama_guard"]["tag"])
        for model in lock["ollama_models"].values():
            self.assertEqual(len(model["digest"]), 64)
        for image in lock["images"].values():
            self.assertTrue(image.endswith(":1.0.0"))
        self.assertEqual(lock["test_tools"]["promptfoo"], "0.121.20")
        self.assertEqual(lock["test_tools"]["garak"], "0.15.1")
        self.assertEqual(len(lock["test_tools"]["node_image_digest"]), 71)

    def test_hub_policy_is_sequential_and_never_downgrades(self) -> None:
        policy = yaml.safe_load((CONTROL / "policies/nemo-policy.yaml").read_text())
        self.assertFalse(policy["execution"]["input_parallel"])
        self.assertFalse(policy["execution"]["output_parallel"])
        self.assertFalse(policy["execution"]["speculative_generation"])
        self.assertFalse(policy["execution"]["automatic_downgrade"])
        self.assertEqual(
            policy["profiles"]["high-assurance"]["input_rails"],
            ["llama_guard", "self_check"],
        )

    def test_presidio_spoke_has_no_application_decision(self) -> None:
        source = (CONTROL / "spokes/presidio-privacy/policy.py").read_text()
        self.assertNotIn('"application_decision"', source)
        self.assertIn('"sanitized_candidate"', source)

    def test_application_authorizes_before_rag_selection(self) -> None:
        policy = load_module(
            "control_plane_application_policy",
            CONTROL / "application-gateway/policy.py",
        )
        public = policy.PRINCIPALS["hub-public-reader-token"]
        with self.assertRaises(policy.AuthorizationError):
            policy.authorize_retrieval(public, "restricted", "customer_support")
        support = policy.PRINCIPALS["hub-support-agent-token"]
        selected = policy.authorize_retrieval(
            support, "restricted", "customer_support"
        )
        self.assertEqual(selected["authorized_by"], "application-policy")
        self.assertNotIn("prohibited", policy.RAG_STORES)

    def test_application_auth_contract_is_rs256_and_stateful(self) -> None:
        source = (CONTROL / "application-gateway/auth.py").read_text()
        server = (CONTROL / "application-gateway/server.py").read_text()
        users = yaml.safe_load((CONTROL / "policies/application-users.yaml").read_text())

        self.assertIn('algorithm="RS256"', source)
        self.assertIn('audience=self.audience', source)
        self.assertIn('issuer=self.issuer', source)
        self.assertIn("refresh-token-reuse", source)
        self.assertIn('@app.post("/.well-known/login")', server)
        self.assertIn('@app.get("/.well-known/jwks.json")', server)
        self.assertEqual(set(users["users"]), {"public-reader", "internal-analyst", "support-agent"})

    def test_logs_exclude_raw_content_fields(self) -> None:
        for relative in (
            "application-gateway/server.py",
            "nemo-policy-hub/server.py",
            "spokes/presidio-privacy/server.py",
        ):
            source = (CONTROL / relative).read_text()
            self.assertNotIn('"message": request.message', source.split("emit_metadata")[-1])
        e2e = (CONTROL / "tests/e2e-control-plane.sh").read_text()
        self.assertIn("! grep -F 'Ignore previous instructions'", e2e)
        self.assertIn("! grep -F 'sk-demo-12345'", e2e)

    def test_existing_serial_sources_are_not_imported_or_modified(self) -> None:
        for relative in (
            "examples/day6/presidio",
            "examples/day6/nemo-guardrails",
            "docker/vuln-rag",
        ):
            self.assertTrue((ROOT / relative).exists())
        readme = (CONTROL / "README.md").read_text()
        self.assertIn("기존 18090~18092 직렬형 실습", readme)

    def test_external_test_tools_target_application_gateway(self) -> None:
        promptfoo = (CONTROL / "tests/promptfoo/promptfooconfig.yaml").read_text()
        self.assertIn("{{env.CONTROL_PLANE_APP_URL}}/api/chat", promptfoo)
        self.assertIn("Bearer {{env.CONTROL_PLANE_ACCESS_TOKEN}}", promptfoo)
        self.assertIn("maxConcurrency: 1", promptfoo)
        self.assertIn("GARAK-PROMOTED", promptfoo)
        generator = json.loads(
            (CONTROL / "tests/garak/rest-generator.json").read_text()
        )["rest"]["RestGenerator"]
        self.assertEqual(generator["uri"], "http://10.0.2.2:18095/api/chat")
        self.assertEqual(
            generator["headers"]["Authorization"],
            "Bearer hub-public-reader-token",
        )

    def test_browser_harness_rejects_direct_internal_calls(self) -> None:
        harness = (ROOT / "tests/browser/run_control_plane_ui.py").read_text()
        self.assertIn("{11434, 18093, 18094}", harness)
        self.assertIn("browser_internal_service_requests", harness)

    def test_publisher_checks_dependency_fail_closed(self) -> None:
        source = (CONTROL / "tests/test_fail_closed.py").read_text()
        self.assertIn("LlamaGuardUnavailable", source)
        self.assertIn("SelfCheckUnavailable", source)
        self.assertIn("main_model.assert_not_awaited()", source)
        self.assertIn('result["reply"], "guardrail infrastructure unavailable"', source)

    def test_all_control_plane_services_share_distributed_tracing(self) -> None:
        telemetry = (CONTROL / "shared/telemetry.py").read_text()
        self.assertIn("FastAPIInstrumentor.instrument_app", telemetry)
        self.assertIn("HTTPXClientInstrumentor().instrument", telemetry)
        for relative, service_name in (
            ("application-gateway/server.py", "llm-security-application-gateway"),
            ("nemo-policy-hub/server.py", "llm-security-nemo-hub"),
            ("spokes/presidio-privacy/server.py", "llm-security-presidio-spoke"),
        ):
            source = (CONTROL / relative).read_text()
            self.assertIn(f'configure_telemetry(app, "{service_name}")', source)
        deploy = (CONTROL / "deploy/start-stack.sh").read_text()
        self.assertIn("OTEL_EXPORTER_OTLP_ENDPOINT=http://llm-sec-alloy:4318", deploy)


if __name__ == "__main__":
    unittest.main()
