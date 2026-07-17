from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LLM_GUARD = ROOT / "examples" / "day6" / "llm-guard"
NEMO = ROOT / "examples" / "day6" / "nemo-guardrails"
UI = ROOT / "docker" / "vuln-rag"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class Day6GuardrailIntegrationTests(unittest.TestCase):
    def test_all_python_sources_parse(self) -> None:
        sources = list(LLM_GUARD.glob("*.py")) + list(NEMO.glob("*.py"))
        sources += [UI / "app" / "guardrails.py", UI / "app" / "main.py"]
        for source in sources:
            with self.subTest(source=source.relative_to(ROOT)):
                ast.parse(read(source), filename=str(source))

    def test_llm_guard_cli_and_server_share_policy_core(self) -> None:
        cli = read(LLM_GUARD / "scan_prompt.py")
        server = read(LLM_GUARD / "server.py")
        entrypoint = read(LLM_GUARD / "entrypoint.py")
        self.assertIn("from guard_core import CASES, GuardCore", cli)
        self.assertIn("from guard_core import FRAMEWORK, FRAMEWORK_VERSION, GuardCore", server)
        self.assertIn('parser.add_argument("--suite"', cli)
        self.assertIn('parser.add_argument("--case"', cli)
        self.assertIn('"--injection-prompt"', cli)
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
        for server in [LLM_GUARD / "server.py", NEMO / "server.py"]:
            text = read(server)
            with self.subTest(server=server.relative_to(ROOT)):
                self.assertTrue(required.issubset(set(fragment for fragment in required if fragment in text)))
                self.assertIn("ENABLE_LAB_ENDPOINTS", text)
                self.assertIn("require_lab_endpoint()", text)
                self.assertIn('GUARD_MODE not in {"off", "audit", "enforce"}', text)

    def test_llm_guard_policy_environment_is_behavioral(self) -> None:
        core = read(LLM_GUARD / "guard_core.py")
        for variable in [
            "PROMPT_INJECTION_ENABLED",
            "PROMPT_INJECTION_THRESHOLD",
            "TOKEN_LIMIT_ENABLED",
            "TOKEN_LIMIT",
            "INVISIBLE_TEXT_ENABLED",
            "OUTPUT_REGEX_ENABLED",
        ]:
            self.assertIn(variable, core)
        self.assertIn("self.settings.scanner_enabled(name)", core)

    def test_ui_calls_only_its_backend_for_chat(self) -> None:
        proxy = read(UI / "app" / "guardrails.py")
        backend = read(UI / "app" / "main.py")
        template = read(UI / "app" / "templates" / "index.html")
        self.assertIn("LLM_GUARD_URL", proxy)
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
