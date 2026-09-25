"""P04 packaging excludes the retired H04 constant-toggle application."""

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "llm-security-control-plane/guided-labs/h04-bedrock-guardrail"


class GuidedP04PackagingTests(unittest.TestCase):
    def test_retired_application_is_absent(self):
        self.assertFalse((LAB / "server.py").exists())
        recipe = (LAB / "Containerfile").read_text()
        self.assertIn('"run_server:configured_app"', recipe)
        self.assertNotIn("h04-bedrock-guardrail/server.py", recipe)
        self.assertIn("h04-bedrock-guardrail/learner.py", recipe)

    def test_runtime_has_no_aws_sdk_or_credentials(self):
        compose = yaml.safe_load(
            (ROOT / "examples/security-monitoring/compose.guided.yaml").read_text()
        )
        for path in LAB.glob("*.py"):
            source = path.read_text()
            self.assertNotIn("import boto3", source, path)
            self.assertNotIn("AWS_SHARED_CREDENTIALS_FILE", source, path)
        service = compose["services"]["guided-h04-guardrail-app"]
        self.assertNotIn("/tmp/.aws", str(service))
        self.assertNotIn("AWS_PROFILE", str(service))


if __name__ == "__main__":
    unittest.main()
