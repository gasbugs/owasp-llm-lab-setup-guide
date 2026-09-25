"""Packaged P03 runner wiring does not contact a provider during startup."""
import os
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import test_guided_p03_run_server as shared


class ConfiguredRunnerTests(unittest.TestCase):
    def environment(self, directory):
        return {"GUIDED_BEDROCK_GATEWAY_URL": "http://gateway.invalid:8080",
                "GUIDED_H03_GATEWAY_TOKEN": "gateway-control",
                "GUIDED_CONTROL_LAB03_TOKEN": "runner-control",
                "GUIDED_VERIFIER_LAB03_TOKEN": "runner-verifier",
                "GUIDED_H03_DATABASE": directory + "/p03.sqlite3"}

    def configured(self, env):
        with patch.dict(os.environ, env, clear=True), patch.dict(sys.modules, {"workflow": shared.flow.workflow}):
            return shared.runner.configured_app()

    def test_real_factory_health_and_build_need_no_network(self):
        with TemporaryDirectory() as directory:
            with patch.object(shared.flow.workflow.Workflow, "_post", side_effect=AssertionError("unexpected network")) as post:
                with TestClient(self.configured(self.environment(directory))) as client:
                    self.assertEqual(client.get("/readyz").json()["provider_check"], "not-run")
                    build = client.get("/v1/build-info", headers={"Authorization": "Bearer runner-verifier"})
                    self.assertEqual(build.status_code, 200)
                    self.assertEqual(set(build.json()["runner_files"]), set(shared.runner.RUNNER_FILES))
                    self.assertEqual(client.get("/v1/build-info").status_code, 401)
                post.assert_not_called()

    def test_required_credentials_and_distinct_roles(self):
        with TemporaryDirectory() as directory:
            for key in ("GUIDED_H03_GATEWAY_TOKEN", "GUIDED_CONTROL_LAB03_TOKEN", "GUIDED_VERIFIER_LAB03_TOKEN"):
                env = self.environment(directory)
                del env[key]
                with self.subTest(key=key), self.assertRaises(KeyError):
                    self.configured(env)
            env = self.environment(directory)
            env["GUIDED_VERIFIER_LAB03_TOKEN"] = env["GUIDED_CONTROL_LAB03_TOKEN"]
            with self.assertRaises(ValueError):
                self.configured(env)

    def test_invalid_gateway_is_rejected_without_request(self):
        with TemporaryDirectory() as directory:
            env = self.environment(directory)
            env["GUIDED_BEDROCK_GATEWAY_URL"] = "http://gateway.invalid/other-path"
            with self.assertRaises(ValueError):
                self.configured(env)


if __name__ == "__main__":
    unittest.main()
