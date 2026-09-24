"""H21 learner policy and downstream evidence contracts."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "llm-security-control-plane/guided-labs/h21-agent-policy"


def load_policy():
    spec = importlib.util.spec_from_file_location("guided_h21_policy", LAB / "policy.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class GuidedH21PolicyTests(unittest.TestCase):
    def test_starter_is_intentionally_vulnerable_but_policy_limits_are_visible(self):
        policy = load_policy()
        admitted = policy.authorize(
            "support-agent",
            "attacker-selected-model",
            "untrusted-notice-mcp",
            "debug_dump",
            9,
            4096,
            1000,
            "other-agent",
        )
        self.assertEqual(admitted.model, "attacker-selected-model")
        self.assertEqual(admitted.server_id, "untrusted-notice-mcp")
        self.assertEqual(admitted.tool, "debug_dump")
        self.assertEqual(admitted.max_tool_calls, 9)
        self.assertEqual(admitted.max_result_bytes, 4096)
        self.assertEqual(admitted.tool_timeout_ms, 1000)
        self.assertEqual(policy.POLICIES["support-agent"]["max_tool_calls"], 2)
        self.assertEqual(policy.POLICIES["support-agent"]["max_result_bytes"], 160)
        self.assertEqual(policy.POLICIES["support-agent"]["tool_timeout_ms"], 250)

    def test_host_uses_real_mcp_client_and_server_owned_cases(self):
        source = (LAB / "host.py").read_text(encoding="utf-8")
        self.assertIn("async with Client(SERVER_URLS[admission.server_id]", source)
        self.assertIn('"forbidden-model"', source)
        self.assertIn('"wrong-audience"', source)
        self.assertIn("min(definition[\"calls\"], admission.max_tool_calls)", source)
        self.assertIn("result_bytes > admission.max_result_bytes", source)

    def test_mcp_server_checks_audience_scope_and_state_owner(self):
        source = (LAB / "mcp_server.py").read_text(encoding="utf-8")
        self.assertIn('claims.get("audience") != SERVER_ID', source)
        self.assertIn('"tools:read" not in claims.get("scope", "").split()', source)
        self.assertIn('claims.get("subject") != state_owner', source)
        self.assertIn('@mcp.tool()', source)

    def test_provider_and_mcp_evidence_are_separate_from_host_receipt(self):
        provider = (LAB / "provider.py").read_text(encoding="utf-8")
        mcp_server = (LAB / "mcp_server.py").read_text(encoding="utf-8")
        self.assertIn('@app.get("/v1/audit/{suite_id}")', provider)
        self.assertIn("def audit_calls", mcp_server)
        self.assertIn("GUIDED_VERIFIER_H21_TOKEN", provider)
        self.assertIn("GUIDED_VERIFIER_H21_TOKEN", mcp_server)


if __name__ == "__main__":
    unittest.main()
