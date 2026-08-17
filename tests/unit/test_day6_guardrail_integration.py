from __future__ import annotations

import ast
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

    def test_presidio_can_wrap_the_nemo_model_path(self) -> None:
        server = read(PRESIDIO / "server.py")
        self.assertIn('NEMO_GUARD_URL = os.getenv("NEMO_GUARD_URL", "")', server)
        self.assertIn('f"{NEMO_GUARD_URL}/api/chat"', server)
        self.assertIn('model_stages = ["nemo_input"]', server)
        self.assertIn('model_stages.extend(["ollama_main", "nemo_output"])', server)
        self.assertIn('"presidio>nemo>ollama>presidio"', server)
        self.assertIn('"inner_guardrail": inner_guardrail', server)

    def test_nemo_uses_slirp_gateway_for_loopback_ollama(self) -> None:
        expected = "http://10.0.2.2:11434"
        self.assertIn(expected, read(NEMO / "nemo_core.py"))
        self.assertIn(expected, read(NEMO / "server.py"))
        for profile in ["input", "output", "integrated"]:
            self.assertIn(expected + "/v1", read(NEMO / "config" / profile / "config.yml"))

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
