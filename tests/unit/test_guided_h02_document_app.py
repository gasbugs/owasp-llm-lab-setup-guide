"""P02 packaging must exclude the retired all-in-one H02 application."""

import unittest
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "llm-security-control-plane/guided-labs/h02-document-ingestion"


class GuidedP02PackagingTests(unittest.TestCase):
    def test_retired_application_is_absent(self):
        self.assertFalse((LAB / "server.py").exists())
        recipe = (LAB / "Containerfile").read_text()
        self.assertIn('"run_server:configured_app"', recipe)
        self.assertNotIn("h02-document-ingestion/server.py", recipe)

    def test_runtime_has_no_aws_sdk_or_credentials(self):
        compose = yaml.safe_load(
            (ROOT / "examples/security-monitoring/compose.guided.yaml").read_text()
        )
        for path in LAB.glob("*.py"):
            source = path.read_text()
            self.assertNotIn("import boto3", source, path)
            self.assertNotIn("AWS_SHARED_CREDENTIALS_FILE", source, path)
        service = compose["services"]["guided-h02-document-app"]
        self.assertNotIn("/tmp/.aws", str(service))
        self.assertNotIn("AWS_PROFILE", str(service))
        self.assertEqual(
            service["environment"]["GUIDED_GATEWAY_URL"],
            "http://guided-bedrock-gateway:8080",
        )


if __name__ == "__main__":
    unittest.main()
