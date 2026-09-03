"""Static contracts for the learner-facing Day 7 guardrail loop assets."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


class Day7GuardrailLoopTests(unittest.TestCase):
    def test_promptfoo_targets_application_and_asserts_control_boundaries(self) -> None:
        source = (ROOT / "examples/day6/promptfoo-guardrail/promptfooconfig.yaml").read_text()
        self.assertIn('url: "{{env.GUARDRAIL_APP_URL}}/api/chat"', source)
        self.assertIn("maxRetries: 0", source)
        self.assertIn('effective_decision === "block"', source)
        self.assertIn('outer_decision === "redact"', source)
        self.assertIn("GARAK-PROMOTED", source)
        self.assertIn("programmatic command", source)

    def test_garak_rest_generator_uses_guarded_application(self) -> None:
        data = json.loads(
            (ROOT / "examples/day6/garak-guardrail/rest-generator.json").read_text()
        )
        config = data["rest"]["RestGenerator"]
        self.assertEqual(config["uri"], "http://day6-guardrail-ui:8000/api/chat")
        self.assertEqual(config["req_template_json_object"], {"message": "$INPUT"})
        self.assertEqual(config["response_json_field"], "reply")

    def test_garak_probe_count_is_bounded_for_learner_run(self) -> None:
        data = yaml.safe_load(
            (ROOT / "examples/day6/garak-guardrail/garak-config.yaml").read_text()
        )
        self.assertEqual(data["run"]["soft_probe_prompt_cap"], 8)
        e2e = (ROOT / "tests/e2e/day6/test_guardrail_policy_loop.sh").read_text()
        self.assertIn("--config /work/garak-config.yaml", e2e)

    def test_garak_image_uses_cpu_torch_and_writable_user_paths(self) -> None:
        source = (ROOT / "examples/day6/garak-guardrail/Containerfile").read_text()
        self.assertIn("https://download.pytorch.org/whl/cpu", source)
        self.assertIn('"torch==${TORCH_VERSION}"', source)
        self.assertIn("HOME=/work", source)
        self.assertIn("XDG_CACHE_HOME=/work/.local/share/garak-cache", source)
        self.assertIn("XDG_CONFIG_HOME=/work/.local/share/garak-config", source)

    def test_server_exposes_policy_identity_and_static_output_contract(self) -> None:
        source = (ROOT / "examples/day6/presidio/server.py").read_text()
        for marker in (
            "policy_version",
            "test_corpus_version",
            '"provider": "amazon-bedrock"',
            "BEDROCK_MODEL_ID",
            '"/api/labs/validate-output-contract"',
            'blocking_reason": "output-contract-invalid"',
            'if guardrail.get("decision") == "infra"',
        ):
            self.assertIn(marker, source)


if __name__ == "__main__":
    unittest.main()
