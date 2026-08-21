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
        self.assertIn("podman container exists", self.source)
        self.assertIn("[REUSE]", self.source)
        self.assertNotIn("down --volumes", self.source)

    def test_script_connects_the_existing_guardrail_chain(self) -> None:
        for value in (
            "day6-nemo-guardrails-api",
            "day6-presidio-api",
            "day6-guardrail-ui",
            "SECURITY_MONITOR_URL=http://llm-sec-gateway:8080",
            "TELEMETRY_INGEST_TOKEN",
        ):
            self.assertIn(value, self.source)
        self.assertIn("--network llm-security-observability", self.source)
        self.assertIn("NEMO_GUARD_URL=http://day6-nemo-guardrails-api:8013", self.source)

    def test_script_verifies_behavior_and_content_safety(self) -> None:
        self.assertIn('decision=="redact"', self.source)
        self.assertIn('decision=="block"', self.source)
        self.assertIn('upstream_called==false', self.source)
        self.assertIn("raw PII found in Presidio logs", self.source)
        self.assertIn("llm_guardrail_decisions_total", self.source)
        self.assertIn("healthy but not connected to Module 08 observability", self.source)
        self.assertIn("--log-driver=k8s-file", self.source)
        self.assertIn("container logs did not reach Loki", self.source)
        self.assertIn("raw PII found in Loki", self.source)


if __name__ == "__main__":
    unittest.main()
