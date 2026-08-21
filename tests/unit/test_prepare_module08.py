from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "infrastructure" / "scripts" / "student" / "prepare-module08.sh"


class PrepareModule08ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_script_is_bounded_and_idempotent(self) -> None:
        self.assertIn("--verify-only", self.source)
        self.assertIn("--repair", self.source)
        self.assertIn("podman image exists", self.source)
        self.assertNotIn("down --volumes", self.source)
        self.assertNotIn('"${COMPOSE[@]}" up --detach --build', self.source)

    def test_script_connects_the_hub_and_spoke_control_plane(self) -> None:
        for value in (
            "llm-security-control-plane",
            "18093/healthz",
            "18094/healthz",
            "18095/healthz",
            "TELEMETRY_INGEST_TOKEN",
        ):
            self.assertIn(value, self.source)
        self.assertIn("podman network exists llm-security-observability", self.source)
        self.assertIn('bash "$CONTROL_ROOT/deploy/start-stack.sh"', self.source)

    def test_project_owned_guardrail_images_build_from_current_checkout(self) -> None:
        self.assertIn('bash "$CONTROL_ROOT/deploy/build-images.sh"', self.source)
        self.assertIn("localhost/llm-security-application-gateway:1.0.0", self.source)

    def test_script_verifies_behavior_and_content_safety(self) -> None:
        self.assertIn('.application_decision == "block"', self.source)
        self.assertIn('.upstream_called == false', self.source)
        self.assertIn("llm_guardrail_decisions_total", self.source)
        self.assertIn("control-plane logs did not reach Loki", self.source)
        self.assertIn('service_name=~"llm-security-.*"', self.source)
        self.assertIn("distributed control-plane trace did not reach Tempo", self.source)
        self.assertIn("llm-security-application-gateway", self.source)
        self.assertIn("llm-security-nemo-hub", self.source)
        self.assertIn("llm-security-presidio-spoke", self.source)


if __name__ == "__main__":
    unittest.main()
