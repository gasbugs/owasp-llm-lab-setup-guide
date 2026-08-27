"""Static and pure-policy checks for the isolated NeMo hub control plane."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
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
    def test_stop_stack_removes_every_control_plane_container(self) -> None:
        stop = (CONTROL / "deploy/stop-stack.sh").read_text()
        for container in (
            "llm-security-application-gateway",
            "llm-security-nemo-hub",
            "llm-security-presidio-spoke",
            "llm-security-bedrock-gateway",
        ):
            self.assertIn(container, stop)

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
        safe_general_safety = {
            "messages": [
                {
                    "content": (
                        "S3 includes credential theft.\n"
                        "User: 비밀번호 변경 절차를 알려 주세요.\n"
                        "Return only Yes to block or No to allow."
                    )
                }
            ]
        }
        self.assertEqual(fake.response_for_openai(safe_self_check), "No")
        self.assertEqual(fake.response_for_openai(unsafe_self_check), "Yes")
        self.assertEqual(fake.response_for_openai(safe_general_safety), "No")

    def test_versions_are_explicit_and_bedrock_model_is_pinned(self) -> None:
        lock = yaml.safe_load((CONTROL / "versions.lock.yaml").read_text())
        self.assertEqual(lock["bedrock"]["provider"], "amazon-bedrock")
        self.assertEqual(lock["bedrock"]["model_id"], "us.amazon.nova-lite-v1:0")
        for image in lock["images"].values():
            self.assertTrue(image.endswith(":1.0.0"))
        self.assertEqual(lock["test_tools"]["promptfoo"], "0.121.20")
        self.assertEqual(lock["test_tools"]["garak"], "0.15.1")
        self.assertEqual(len(lock["test_tools"]["node_image_digest"]), 71)

    def test_runtime_contract_matches_server_and_browser_harness(self) -> None:
        contract = yaml.safe_load((CONTROL / "runtime-contract.yaml").read_text())
        self.assertEqual(contract["model_id"], "us.amazon.nova-lite-v1:0")
        self.assertEqual(contract["main_stage"], "bedrock_main")
        self.assertEqual(contract["services"]["application"]["host_port"], 18095)
        harness = (ROOT / "tests/browser/run_control_plane_ui.py").read_text()
        self.assertIn('"bedrock_main" in normal_stage_order', harness)
        self.assertIn('"width": 390', harness)
        self.assertIn("mobile_overflow", harness)

    def test_dialog_image_uses_the_pinned_runtime_and_dependencies(self) -> None:
        dialog = ROOT / "examples/day6/nemo-guardrails"
        containerfile = (dialog / "Containerfile").read_text()
        lock = yaml.safe_load((CONTROL / "versions.lock.yaml").read_text())
        self.assertIn(lock["runtime"]["python_image_digest"], containerfile)
        requirements = (dialog / "requirements.txt").read_text().splitlines()
        for package in ("fastapi", "httpx", "nemoguardrails", "uvicorn"):
            expected = f'{package}=={lock["python_packages"][package]}'
            self.assertIn(expected, requirements)

    def test_hub_policy_is_sequential_and_never_downgrades(self) -> None:
        policy = yaml.safe_load((CONTROL / "policies/control-plane-policy.yaml").read_text())
        self.assertFalse(policy["execution"]["input_parallel"])
        self.assertFalse(policy["execution"]["output_parallel"])
        self.assertFalse(policy["execution"]["speculative_generation"])
        self.assertFalse(policy["execution"]["automatic_downgrade"])
        self.assertEqual(
            policy["assurance_profiles"]["high-assurance"]["input_rails"],
            ["nova_general_safety", "application_self_check"],
        )

    def test_official_nemo_configs_are_separate_from_control_plane_policy(self) -> None:
        policy = yaml.safe_load((CONTROL / "policies/control-plane-policy.yaml").read_text())
        self.assertNotIn("models", policy)
        self.assertNotIn("rails", policy)
        for implementation in policy["rail_implementations"].values():
            config = yaml.safe_load(
                (CONTROL / "nemo-policy-hub/config" / implementation["config_directory"] / "config.yml").read_text()
            )
            self.assertEqual(config["rails"]["input"]["flows"], ["self check input"])
            self.assertEqual(config["rails"]["output"]["flows"], ["self check output"])

    def test_empty_assurance_profile_is_structurally_valid(self) -> None:
        source = (CONTROL / "nemo-policy-hub/hub_core.py").read_text()
        self.assertIn('for rail_name in CONTROL_PLANE_POLICY["assurance_profiles"]', source)
        self.assertNotIn("Field(min_length=1", (CONTROL / "policies/control-plane-policy.yaml").read_text())

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
        self.assertEqual(selected["allowed_source_suffixes"], ["/restricted-incident.md"])
        self.assertNotIn("chunks", selected)
        self.assertNotIn("prohibited", policy.RAG_STORES)

    def test_module08_aws_restore_is_separate_and_idempotent(self) -> None:
        source = (CONTROL / "deploy/restore-module08-aws.sh").read_text()
        runtime = (CONTROL / "deploy/prepare-module08-runtime.sh").read_text()
        env_helper = (CONTROL / "deploy/lib/module08-compose-env.sh").read_text()
        self.assertIn("--verify-only", source)
        self.assertIn("--repair", source)
        self.assertIn("owasp-llm-module08", source)
        self.assertNotIn("owasp-llm-course-knowledge-base", source)
        self.assertIn("module08-aws.env", source)
        self.assertIn("FAILED|DELETE_UNSUCCESSFUL", source)
        self.assertIn("DELETING", source)
        self.assertIn("wait_for_data_source_available", source)
        self.assertIn("knowledge_base=DEFERRED", runtime)
        self.assertNotIn("create-knowledge-base", runtime)
        self.assertIn("write_module08_compose_env", runtime)
        self.assertIn('openssl rand -hex "$bytes"', env_helper)
        self.assertIn("write_module08_compose_env", source)

    def test_module08_runtime_preparation_defers_knowledge_base_and_reuses_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            bin_dir = temp / "bin"
            state_dir = temp / "state"
            bin_dir.mkdir()
            state_dir.mkdir()
            (bin_dir / "aws").write_text("#!/bin/sh\nprintf '{}\\n'\n")
            (bin_dir / "openssl").write_text("#!/bin/sh\nprintf 'generated-secret'\n")
            (bin_dir / "aws").chmod(0o755)
            (bin_dir / "openssl").chmod(0o755)
            compose_env = state_dir / "module08-compose.env"
            compose_env.write_text("BEDROCK_GATEWAY_TOKEN=preserved-token\n")

            result = subprocess.run(
                ["bash", str(CONTROL / "deploy/prepare-module08-runtime.sh")],
                check=True,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PATH": f"{bin_dir}:{os.environ['PATH']}",
                    "MODULE08_STATE_DIR": str(state_dir),
                    "AWS_REGION": "us-east-1",
                    "AWS_PROFILE": "course",
                },
            )

            values = dict(
                line.split("=", 1)
                for line in compose_env.read_text().splitlines()
            )
            self.assertIn("knowledge_base=DEFERRED", result.stdout)
            self.assertEqual(values["MODULE08_KNOWLEDGE_BASE_ID"], "")
            self.assertEqual(values["BEDROCK_GATEWAY_TOKEN"], "preserved-token")
            self.assertEqual(values["AWS_PROFILE"], "course")
            self.assertEqual(stat.S_IMODE(compose_env.stat().st_mode), 0o600)

    def test_compose_disables_pod_mode_for_keep_id_services(self) -> None:
        compose = (CONTROL / "compose.yaml").read_text()
        parsed = yaml.safe_load(compose)
        self.assertFalse(parsed["x-podman"]["in_pod"])
        self.assertEqual(
            parsed["services"]["bedrock-gateway"]["userns_mode"],
            "keep-id:uid=65532,gid=65532",
        )
        self.assertEqual(
            parsed["services"]["application"]["userns_mode"],
            "keep-id:uid=65532,gid=65532",
        )

    def test_module08_cleanup_is_aws_only_and_preserves_local_runtime(self) -> None:
        source = (CONTROL / "deploy/cleanup-module08-aws.sh").read_text()
        self.assertIn("owasp-llm-module08", source)
        self.assertIn("delete-data-source", source)
        self.assertIn("delete-knowledge-base", source)
        self.assertIn("delete-vector-bucket", source)
        self.assertNotIn("podman", source)

    def test_module09_repair_restores_module08_aws_before_local_stack(self) -> None:
        source = (
            ROOT / "infrastructure/scripts/student/prepare-module08.sh"
        ).read_text()
        restore = 'bash "$CONTROL_ROOT/deploy/restore-module08-aws.sh" --repair'
        start = 'bash "$CONTROL_ROOT/deploy/start-stack.sh"'
        self.assertIn(restore, source)
        self.assertIn(start, source)
        self.assertLess(source.index(restore), source.index(start))

    def test_gateway_owns_bedrock_retrieval_and_pricing_metadata(self) -> None:
        gateway = (CONTROL / "bedrock-gateway/server.py").read_text()
        application = (CONTROL / "application-gateway/server.py").read_text()
        self.assertIn('@app.post("/v1/retrieve")', gateway)
        self.assertIn("BEDROCK_AGENT_RUNTIME.retrieve", gateway)
        self.assertIn("bedrock_pricing_info", gateway)
        self.assertIn("require_gateway_token", gateway)
        self.assertIn("BEDROCK_GATEWAY_TOKEN", application)
        self.assertIn('headers={"Authorization": f"Bearer {BEDROCK_GATEWAY_TOKEN}"}', application)
        self.assertIn('f"{MODEL_GATEWAY_URL}/v1/retrieve"', application)
        self.assertIn("allowed_suffixes", application)

    def test_gateway_token_is_shared_by_every_bedrock_caller(self) -> None:
        start = (CONTROL / "deploy/start-stack.sh").read_text()
        hub = (CONTROL / "nemo-policy-hub/hub_core.py").read_text()
        nemo_config = (CONTROL / "nemo-policy-hub/config/nova-general-safety/config.yml").read_text()
        fake = (CONTROL / "tests/fake_bedrock_gateway.py").read_text()
        self.assertIn("BEDROCK_GATEWAY_TOKEN:?Run prepare-module08-runtime.sh", start)
        self.assertIn("api_key_env_var: BEDROCK_GATEWAY_TOKEN", nemo_config)
        self.assertNotIn('"api_key": BEDROCK_GATEWAY_TOKEN', hub)
        self.assertIn('Bearer {BEDROCK_GATEWAY_TOKEN}', hub)
        self.assertIn("invalid Bedrock Gateway token", fake)

    def test_compose_secrets_are_generated_and_have_no_runtime_defaults(self) -> None:
        runtime = (CONTROL / "deploy/prepare-module08-runtime.sh").read_text()
        env_helper = (CONTROL / "deploy/lib/module08-compose-env.sh").read_text()
        compose = (CONTROL / "compose.yaml").read_text()
        monitor_compose = (ROOT / "examples/security-monitoring/compose.yaml").read_text()
        self.assertIn("write_module08_compose_env", runtime)
        self.assertIn("umask 077", env_helper)
        self.assertIn('openssl rand -hex "$bytes"', env_helper)
        for secret in (
            "PRESIDIO_INTERNAL_TOKEN",
            "APPLICATION_INTERNAL_TOKEN",
            "BEDROCK_GATEWAY_TOKEN",
            "AUTH_ADMIN_TOKEN",
        ):
            self.assertIn(f"{secret}:?Run prepare-module08-runtime.sh", compose)
        self.assertNotIn(":-module08-bedrock-gateway-token", compose)
        self.assertNotIn(":-llm-monitor-acme-token", monitor_compose)

    def test_application_auth_contract_is_rs256_and_stateful(self) -> None:
        source = (CONTROL / "application-gateway/auth.py").read_text()
        server = (CONTROL / "application-gateway/server.py").read_text()
        users = yaml.safe_load((CONTROL / "policies/application-users.yaml").read_text())

        self.assertIn('algorithm="RS256"', source)
        self.assertIn("pbkdf2_hmac", source)
        self.assertNotIn("password", users["users"]["public-reader"])
        self.assertIn("password_hash", users["users"]["public-reader"])
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
        self.assertEqual(
            generator["uri"],
            "http://llm-security-application-gateway:8000/api/chat",
        )
        self.assertEqual(
            generator["headers"]["Authorization"],
            "Bearer hub-public-reader-token",
        )

    def test_browser_harness_rejects_direct_internal_calls(self) -> None:
        harness = (ROOT / "tests/browser/run_control_plane_ui.py").read_text()
        self.assertIn("{18093, 18094, 18096}", harness)
        self.assertIn("browser_internal_service_requests", harness)

    def test_publisher_checks_dependency_fail_closed(self) -> None:
        source = (CONTROL / "tests/test_fail_closed.py").read_text()
        self.assertIn("ContentSafetyUnavailable", source)
        self.assertIn("SelfCheckUnavailable", source)
        self.assertIn("main_model.assert_not_awaited()", source)
        self.assertIn('result["reply"], "guardrail infrastructure unavailable"', source)

    def test_all_control_plane_services_share_distributed_tracing(self) -> None:
        telemetry = (CONTROL / "shared/telemetry.py").read_text()
        self.assertIn("FastAPIInstrumentor.instrument_app", telemetry)
        self.assertIn("HTTPXClientInstrumentor().instrument", telemetry)
        for relative in (
            "application-gateway/requirements.txt",
            "bedrock-gateway/requirements.txt",
            "nemo-policy-hub/requirements.txt",
            "spokes/presidio-privacy/requirements.txt",
        ):
            requirements = (CONTROL / relative).read_text().splitlines()
            self.assertIn(
                "httpx==0.28.1",
                requirements,
                f"{relative} must install telemetry.py's direct httpx dependency",
            )
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
