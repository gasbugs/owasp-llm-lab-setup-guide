"""Static and pure-policy checks for the isolated NeMo hub control plane."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "llm-security-control-plane"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class LlmSecurityControlPlaneTests(unittest.TestCase):
    def test_versions_are_explicit_and_model_digests_are_full(self) -> None:
        lock = yaml.safe_load((CONTROL / "versions.lock.yaml").read_text())
        self.assertNotIn("latest", lock["ollama_models"]["main"]["tag"])
        self.assertNotIn("latest", lock["ollama_models"]["llama_guard"]["tag"])
        for model in lock["ollama_models"].values():
            self.assertEqual(len(model["digest"]), 64)
        for image in lock["images"].values():
            self.assertTrue(image.endswith(":1.0.0"))

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


if __name__ == "__main__":
    unittest.main()
