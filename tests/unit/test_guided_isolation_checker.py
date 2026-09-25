"""Negative cases for resolved deployment isolation; no running infrastructure needed."""

import copy
import importlib.util
import os
from pathlib import Path
import re
import shutil
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("guided_isolation", Path(__file__).resolve().parents[2] / "tools/check_guided_isolation.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def deployment(prefix, port):
    return {
        "name": prefix,
        "networks": {"default": {"name": prefix + "-network"}},
        "volumes": {"state": {"name": prefix + "-state"}},
        "services": {"web": {
            "container_name": prefix + "-web", "networks": {"default": {}},
            "ports": [{"published": str(port), "target": 8000, "host_ip": "127.0.0.1", "protocol": "tcp"}],
            "volumes": [{"type": "bind", "source": "/shared/credentials", "target": "/credentials", "read_only": True}],
        }},
    }


class IsolationCheckerTests(unittest.TestCase):
    def setUp(self):
        self.two = deployment("tenant02", 18097)
        self.three = deployment("tenant03", 28097)

    def errors(self):
        return checker.check_isolation(self.two, self.three)

    def test_separate_projects_same_internal_port_and_readonly_credentials(self):
        self.assertEqual(self.errors(), [])

    def test_override_collision_regardless_of_protocol_and_address(self):
        self.three["services"]["web"]["ports"][0].update(published="18097", host_ip="::", protocol="udp")
        self.assertTrue(any("host port 18097" in error for error in self.errors()))

    def test_port_range_overlap(self):
        self.three["services"]["web"]["ports"][0]["published"] = "18096-18098"
        self.assertTrue(any("host port 18097" in error for error in self.errors()))

    def test_random_port_is_rejected(self):
        self.three["services"]["web"]["ports"][0].pop("published")
        with self.assertRaises(ValueError):
            self.errors()

    def test_duplicate_listeners_within_03(self):
        self.three["services"]["other"] = copy.deepcopy(self.three["services"]["web"])
        self.assertTrue(any("duplicate listeners" in error for error in self.errors()))

    def test_network_container_volume_and_project_collisions(self):
        for key in ("name", "networks", "volumes", "services"):
            with self.subTest(key=key):
                original = self.three[key]
                self.three[key] = copy.deepcopy(self.two[key])
                self.assertTrue(self.errors())
                self.three[key] = original

    def test_parent_bind_mount_cannot_modify_other_tenant_readonly_state(self):
        self.three["services"]["web"]["volumes"][0].update(source="/shared", read_only=False)
        errors = self.errors()
        self.assertTrue(any("writable bind overlap" in error for error in errors))
        self.assertFalse(any("/shared" in error for error in errors))

    def test_sibling_writable_mounts_are_independent(self):
        self.two["services"]["web"]["volumes"][0].update(source="/state/two", read_only=False)
        self.three["services"]["web"]["volumes"][0].update(source="/state/three", read_only=False)
        self.assertEqual(self.errors(), [])

    def test_network_bypasses_are_rejected(self):
        for mode in ("host", "service:other", "container:other", "none"):
            with self.subTest(mode=mode):
                self.three["services"]["web"]["network_mode"] = mode
                self.assertTrue(any("network_mode" in error for error in self.errors()))

    def test_external_network_is_rejected(self):
        self.three["networks"]["default"]["external"] = True
        self.assertTrue(any("external networks" in error for error in self.errors()))

    @unittest.skipUnless(shutil.which("docker"), "Docker Compose required")
    def test_actual_compose_defaults_and_resolved_override(self):
        root = Path(__file__).resolve().parents[2]
        guided = root / "examples/security-monitoring/compose.guided.yaml"
        others = [root / path for path in (
            "llm-security-control-plane/compose.yaml",
            "examples/security-monitoring/compose.yaml",
            "examples/runtime-security/compose.yaml",
            "examples/runtime-security/compose.mcp.yaml",
        )]
        # Only config is rendered. These placeholders never reach a running service.
        env = {key: value for key, value in os.environ.items() if key in ("PATH", "HOME", "DOCKER_CONFIG")}
        for path in [guided, *others]:
            for key in re.findall(r"\$\{(\w+):\?", path.read_text()):
                if key not in env:
                    env[key] = "isolation-test-placeholder"
        env.update(LOCAL_UID=str(os.getuid()), LOCAL_GID=str(os.getgid()), AWS_CREDENTIALS_DIR="/tmp/isolation-no-credentials")
        with patch.dict(os.environ, env, clear=True):
            three = checker.render([str(guided)], None)
            for path in others:
                with self.subTest(compose=str(path.relative_to(root))):
                    two = checker.render([str(path)], None)
                    self.assertEqual(checker.check_isolation(two, three), [])
            two = checker.render([str(others[0])], None)
            collision = next(iter(checker.port_numbers(two)))
            os.environ["GUIDED_HOST_PORT"] = str(collision)
            overridden = checker.render([str(guided)], None)
            self.assertTrue(any(f"host port {collision}" in error for error in checker.check_isolation(two, overridden)))


if __name__ == "__main__":
    unittest.main()
