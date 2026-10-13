"""P03 packaging excludes the retired H03 coordinator."""

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "llm-security-control-plane/guided-labs/h03-ingestion-search"


class GuidedP03PackagingTests(unittest.TestCase):
    def test_retired_application_is_absent(self):
        self.assertFalse((LAB / "server.py").exists())
        recipe = (LAB / "Containerfile").read_text()
        self.assertIn('"run_server:configured_app"', recipe)
        self.assertNotIn("h03-ingestion-search/server.py", recipe)
        self.assertIn("h03-ingestion-search/learner.py", recipe)

    def test_runtime_keeps_aws_credentials_out_of_compose(self):
        compose = yaml.safe_load(
            (ROOT / "examples/security-monitoring/compose.guided.yaml").read_text()
        )
        self.assertIn("import boto3", (LAB / "native_runtime.py").read_text())
        for path in LAB.glob("*.py"):
            self.assertNotIn("AWS_SHARED_CREDENTIALS_FILE", path.read_text(), path)
        service = compose["services"]["guided-h03-sync-app"]
        self.assertNotIn("/tmp/.aws", str(service))
        self.assertNotIn("AWS_PROFILE", str(service))


if __name__ == "__main__":
    unittest.main()
