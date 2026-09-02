from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "infrastructure" / "scripts" / "student" / "deploy-module08-complete.sh"


class DeployModule08CompleteContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_cleanup_is_limited_to_module07_and_module08(self) -> None:
        for name in (
            "day6-guardrail-ui",
            "day6-presidio-api",
            "llm-security-nemo-dialog-rails",
            "llm-security-application-gateway",
            "llm-security-nemo-hub",
            "llm-security-presidio-spoke",
            "llm-security-observability_mimir-data",
        ):
            self.assertIn(name, self.source)
        self.assertNotIn("docker system prune", self.source)
        self.assertNotIn("docker volume prune", self.source)
        self.assertNotIn("docker rm -a", self.source)

    def test_bootstrap_runtime_is_preserved_and_required(self) -> None:
        self.assertIn("docker container inspect lab-ollama", self.source)
        self.assertNotIn('docker rm -f lab-ollama', self.source)
        self.assertNotIn("ollama-models", self.source)

    def test_complete_deployment_builds_and_verifies_current_source(self) -> None:
        self.assertIn("docker compose --project-name llm-security-observability", self.source)
        self.assertIn('"${COMPOSE[@]}" up --detach --build', self.source)
        self.assertIn('bash "$PREPARE_SCRIPT" --repair', self.source)
        self.assertIn("[READY] Continue with Module 08 signal collection labs", self.source)
        self.assertIn("traces_spanmetrics_calls_total", self.source)
        self.assertIn("traces_service_graph_request_total", self.source)
        self.assertIn("llm-security-prometheus", self.source)


if __name__ == "__main__":
    unittest.main()
