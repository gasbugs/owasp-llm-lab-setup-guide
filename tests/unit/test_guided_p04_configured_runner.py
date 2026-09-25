"""P04 default factory and explicit packaging, without AWS or network calls."""
import os
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import test_guided_p04_run_server as shared
from test_guided_packaging import copy_sources


class ConfiguredRunnerTests(unittest.TestCase):
    def environment(self, directory):
        return {"GUIDED_BEDROCK_GATEWAY_URL": "http://gateway.invalid:8080",
                "GUIDED_H04_GATEWAY_TOKEN": "g" * 32,
                "GUIDED_CONTROL_LAB04_TOKEN": "c" * 32,
                "GUIDED_VERIFIER_LAB04_TOKEN": "v" * 32,
                "GUIDED_H04_DATABASE": directory + "/p04.sqlite3"}

    def configured(self, env):
        with patch.dict(os.environ, env, clear=True), patch.dict(sys.modules, {"workflow": shared.flow.workflow}):
            return shared.runner.configured_app()

    def test_factory_health_and_build_need_no_network_or_learner_execution(self):
        with TemporaryDirectory() as directory:
            with patch.object(shared.flow.workflow.Workflow, "_post", side_effect=AssertionError("unexpected network")) as post:
                with TestClient(self.configured(self.environment(directory))) as client:
                    self.assertEqual(client.get("/readyz").json()["provider_check"], "not-run")
                    build = client.get("/v1/build-info", headers={"Authorization": "Bearer " + "v" * 32})
                    self.assertEqual(build.status_code, 200)
                    self.assertEqual(set(build.json()["runner_files"]), set(shared.runner.RUNNER_FILES))
                    self.assertEqual(client.get("/v1/build-info").status_code, 401)
                    self.assertEqual(client.get("/v1/build-info", headers={"Authorization": "Bearer " + "c" * 32}).status_code, 401)
                post.assert_not_called()

    def test_missing_short_or_reused_credentials_fail_startup(self):
        with TemporaryDirectory() as directory:
            for key in ("GUIDED_H04_GATEWAY_TOKEN", "GUIDED_CONTROL_LAB04_TOKEN", "GUIDED_VERIFIER_LAB04_TOKEN"):
                env = self.environment(directory)
                del env[key]
                with self.subTest(key=key), self.assertRaises(KeyError):
                    self.configured(env)
                env[key] = "short"
                with self.subTest(key=key), self.assertRaises(ValueError):
                    self.configured(env)
            env = self.environment(directory)
            env["GUIDED_VERIFIER_LAB04_TOKEN"] = env["GUIDED_CONTROL_LAB04_TOKEN"]
            with self.assertRaises(ValueError):
                self.configured(env)

    def test_invalid_gateway_origin_fails_before_request(self):
        with TemporaryDirectory() as directory:
            env = self.environment(directory)
            for address in ("http://gateway.invalid/other-path", "http://user:secret@example.com", "file:///tmp/state"):
                env["GUIDED_BEDROCK_GATEWAY_URL"] = address
                with self.subTest(address=address), self.assertRaises(ValueError):
                    self.configured(env)

    def test_recipe_contains_only_starter_and_runtime_and_uses_the_real_factory(self):
        recipe = (shared.LAB / "Containerfile").read_text()
        sources = set(copy_sources(recipe))
        prefix = "guided-labs/h04-bedrock-guardrail/"
        self.assertEqual(sources, {prefix + name for name in (*shared.runner.RUNNER_FILES, "learner.py")})
        self.assertIn('"run_server:configured_app", "--factory"', recipe)
        self.assertNotIn("server.py", sources)
        self.assertIn("USER 65532:65532", recipe)


if __name__ == "__main__":
    unittest.main()
