from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRESIDIO = ROOT / "examples" / "day6" / "presidio"
NEMO = ROOT / "examples" / "day6" / "nemo-guardrails"
UI = ROOT / "docker" / "vuln-rag"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class Day6GuardrailIntegrationTests(unittest.TestCase):
    def test_all_python_sources_parse(self) -> None:
        sources = list(PRESIDIO.glob("*.py")) + list(NEMO.glob("*.py"))
        sources += [UI / "app" / "guardrails.py", UI / "app" / "main.py"]
        for source in sources:
            with self.subTest(source=source.relative_to(ROOT)):
                ast.parse(read(source), filename=str(source))

    def test_presidio_cli_and_server_share_policy_core(self) -> None:
        cli = read(PRESIDIO / "scan_pii.py")
        server = read(PRESIDIO / "server.py")
        entrypoint = read(PRESIDIO / "entrypoint.py")
        self.assertIn("from presidio_core import CASES, PresidioCore", cli)
        self.assertIn("from presidio_core import FRAMEWORK, FRAMEWORK_VERSION, PresidioCore", server)
        self.assertIn('parser.add_argument("--suite"', cli)
        self.assertIn('parser.add_argument("--case"', cli)
        self.assertIn('parser.add_argument("--text"', cli)
        self.assertIn('parser.add_argument("--direction"', cli)
        self.assertIn('run_mode == "server"', entrypoint)
        self.assertIn('args[0] == "serve"', entrypoint)

    def test_required_http_contract_and_lab_gate_exist(self) -> None:
        required = {
            '@app.get("/healthz")',
            '@app.get("/api/guardrails/policy")',
            '@app.post("/api/scan")',
            '@app.post("/api/scan-output")',
            '@app.post("/api/chat")',
            '@app.post("/api/labs/suite")',
        }
        for server in [PRESIDIO / "server.py", NEMO / "server.py"]:
            text = read(server)
            with self.subTest(server=server.relative_to(ROOT)):
                self.assertTrue(required.issubset(set(fragment for fragment in required if fragment in text)))
                self.assertIn("ENABLE_LAB_ENDPOINTS", text)
                self.assertIn("require_lab_endpoint()", text)
                self.assertIn('GUARD_MODE not in {"off", "audit", "enforce"}', text)

    def test_presidio_has_learner_visible_adjacent_secure_coding_boundary(self) -> None:
        server = read(PRESIDIO / "server.py")
        secure_coding = read(PRESIDIO / "secure_coding.py")
        containerfile = read(PRESIDIO / "Containerfile")
        self.assertIn('NODEGOAT-LAB: DAY6', secure_coding)
        self.assertIn('VULNERABLE-ACTIVE', secure_coding)
        self.assertIn('SAFE-ENABLE', secure_coding)
        self.assertIn('select_personal_data_policy', server)
        self.assertIn('@app.post("/api/labs/secure-coding/scan")', server)
        self.assertIn('secure_coding.py', containerfile)

    def test_presidio_policy_environment_is_behavioral(self) -> None:
        core = read(PRESIDIO / "presidio_core.py")
        for variable in [
            "PRESIDIO_SCORE_THRESHOLD",
            "PRESIDIO_ENTITIES",
            "PRESIDIO_INPUT_ENABLED",
            "PRESIDIO_OUTPUT_ENABLED",
        ]:
            self.assertIn(variable, core)
        self.assertIn("AnalyzerEngine(", core)
        self.assertIn("AnonymizerEngine()", core)
        self.assertIn('supported_entity="KR_RRN"', core)
        self.assertIn('supported_entity="DEMO_API_KEY"', core)

    def test_korean_rrn_pattern_matches_when_a_particle_is_attached(self) -> None:
        """한글 조사가 붙어도 숫자 경계 기반 주민번호 패턴은 탐지해야 한다."""
        core_tree = ast.parse(read(PRESIDIO / "presidio_core.py"))
        pattern_node = next(
            node.value
            for node in core_tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "KR_RRN_PATTERN"
                for target in node.targets
            )
        )
        pattern = ast.literal_eval(pattern_node)

        self.assertIsNotNone(
            re.search(pattern, "123456-1234567는 개인 식별정보인가? 어떻게 생각해?")
        )
        self.assertIsNone(re.search(pattern, "9123456-12345678"))

    def test_presidio_can_wrap_the_nemo_model_path(self) -> None:
        server = read(PRESIDIO / "server.py")
        self.assertIn('NEMO_GUARD_URL = os.getenv("NEMO_GUARD_URL", "")', server)
        self.assertIn('f"{NEMO_GUARD_URL}/api/chat"', server)
        self.assertIn('model_stages = ["nemo_input"]', server)
        self.assertIn('model_stages.extend(["ollama_main", "nemo_output"])', server)
        self.assertIn('"presidio>nemo>ollama>presidio"', server)
        self.assertIn('"inner_guardrail": inner_guardrail', server)

    def test_guardrails_authenticate_monitor_forwarding(self) -> None:
        for server_path in [PRESIDIO / "server.py", NEMO / "server.py"]:
            server = read(server_path)
            with self.subTest(server=server_path.relative_to(ROOT)):
                self.assertIn("TELEMETRY_INGEST_TOKEN", server)
                self.assertIn('headers={"X-Telemetry-Token": TELEMETRY_INGEST_TOKEN}', server)

    def test_presidio_logs_and_chat_evidence_exclude_content(self) -> None:
        server = read(PRESIDIO / "server.py")
        for field in [
            '"original_text"',
            '"sanitized_text"',
            '"input_prompt"',
            '"model_output"',
            '"reply"',
        ]:
            self.assertIn(field, server)
        self.assertIn("safe_event = metadata_only(event)", server)
        self.assertIn("json=safe_event", server)
        self.assertIn("input_checks.append(scan_metadata(input_result))", server)
        self.assertIn("output_checks.append(scan_metadata(output_result))", server)

    def test_nemo_uses_slirp_gateway_for_loopback_ollama(self) -> None:
        expected = "http://10.0.2.2:11434"
        self.assertIn(expected, read(NEMO / "nemo_core.py"))
        self.assertIn(expected, read(NEMO / "server.py"))
        for profile in ["input", "output", "integrated"]:
            self.assertIn(expected + "/v1", read(NEMO / "config" / profile / "config.yml"))

    def test_nemo_main_path_keeps_dialog_generation_enabled(self) -> None:
        core = read(NEMO / "nemo_core.py")
        self.assertIn('options=log_options(["dialog"])', core)
        self.assertNotIn("options=log_options([])", core)

    def test_nemo_dialog_uses_colang_and_read_only_custom_action(self) -> None:
        server = read(NEMO / "server.py")
        flows = read(NEMO / "config" / "dialog" / "flows.co")
        actions = read(NEMO / "config" / "dialog" / "config.py")
        self.assertIn('@app.post("/api/labs/dialog")', server)
        self.assertIn("define flow security contact lookup", flows)
        self.assertIn("execute get_security_contact()", flows)
        self.assertIn("define flow block state changing transfer", flows)
        self.assertIn('app.register_action(get_security_contact, "get_security_contact")', actions)
        self.assertNotIn("transfer_money", actions)

    def test_nemo_retrieval_rail_delegates_pii_to_presidio(self) -> None:
        server = read(NEMO / "server.py")
        config = read(NEMO / "config" / "retrieval" / "config.yml")
        flows = read(NEMO / "config" / "retrieval" / "flows.co")
        actions = read(NEMO / "config" / "retrieval" / "config.py")
        self.assertIn('@app.post("/api/labs/retrieval")', server)
        self.assertIn("mask retrieval with Presidio", config)
        self.assertIn("execute mask_retrieval_with_presidio", flows)
        self.assertIn('f"{PRESIDIO_URL}/api/scan"', actions)
        self.assertIn("sanitized_text", actions)
        self.assertIn('app.register_action(retrieve_lab_chunks, "retrieve_relevant_chunks")', actions)
        self.assertIn("cache_dir: /opt/nemo-cache", config)

    def test_ui_calls_only_its_backend_for_chat(self) -> None:
        proxy = read(UI / "app" / "guardrails.py")
        backend = read(UI / "app" / "main.py")
        template = read(UI / "app" / "templates" / "index.html")
        self.assertIn("PRESIDIO_URL", proxy)
        self.assertIn("NEMO_GUARD_URL", proxy)
        self.assertIn("guardrail_proxy.chat(req.message)", backend)
        self.assertIn("fetch('/api/chat'", template)
        self.assertNotIn("host.containers.internal", template)
        self.assertNotIn("11434", template)
        self.assertIn("innerGuardrail?.decision === 'block'", template)
        self.assertIn("innerGuardrail.upstream_called", template)
        self.assertIn("innerGuardrail?.blocking_reason", template)
        for field in [
            "engine",
            "mode",
            "decision",
            "upstream_called",
            "duration_ms",
            "blocking_reason",
            "input_checks",
            "output_checks",
        ]:
            self.assertIn(field, template)

    def test_no_public_ingress_is_added_for_integration_ports(self) -> None:
        terraform = "\n".join(
            read(path) for path in (ROOT / "infrastructure" / "terraform").glob("*.tf")
        )
        for port in ["18090", "18091", "18092"]:
            self.assertNotIn(port, terraform)


if __name__ == "__main__":
    unittest.main()
