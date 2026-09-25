"""Read-only deployment gates: no provider calls or learner suites are run."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
GUIDED = ROOT / "examples/security-monitoring/compose.guided.yaml"
TENANT02 = (
    ROOT / "llm-security-control-plane/compose.yaml",
    ROOT / "examples/security-monitoring/compose.yaml",
    ROOT / "examples/runtime-security/compose.yaml",
    ROOT / "examples/runtime-security/compose.mcp.yaml",
)


def defaults(value: str) -> str:
    return re.sub(r"\$\{\w+:-([^}]+)\}", r"\1", value)


def published_ports(document: dict) -> set[int]:
    return {
        int(defaults(str(port)).split(":")[-2])
        for service in document["services"].values()
        for port in service.get("ports", [])
    }


class GuidedDeploymentIsolationTests(unittest.TestCase):
    def test_ci_covers_all_public_practices_with_isolated_publishers(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/guided-practice-e2e.yml").read_text())
        jobs = workflow["jobs"]
        reused = {"P" + item[1:] for group in jobs["reused-services"]["strategy"]["matrix"]["activities"]
                  for item in group.split()}
        implemented = set(jobs["implementation-services"]["strategy"]["matrix"]["practice"])
        self.assertFalse(reused & implemented)
        self.assertEqual(reused | implemented, {f"P{number:02}" for number in range(1, 23)})
        self.assertIn("--startup-only", jobs["canonical-startup"]["steps"][-1]["run"])
        self.assertIn("check_guided_problem_surface.py", jobs["problem-surface"]["steps"][-1]["run"])

    def setUp(self):
        self.source = GUIDED.read_text()
        self.compose = yaml.safe_load(self.source)

    def test_common_start_has_no_transitive_learner_dependency(self):
        services = self.compose["services"]
        common = {"guided-front-proxy", "guided-control-center", "guided-evidence-verifier"}
        for root in common:
            pending = [root]
            visited = set()
            while pending:
                service = pending.pop()
                if service in visited:
                    continue
                visited.add(service)
                dependencies = set(services[service].get("depends_on", {}))
                self.assertFalse(dependencies - common, (root, dependencies - common))
                pending.extend(dependencies)

    def test_tenant02_and_tenant03_defaults_do_not_overlap(self):
        ports = published_ports(self.compose)
        self.assertEqual(ports, {28097, 28192, 25500, 28098, 23001, 23002})
        names = {service["container_name"] for service in self.compose["services"].values()}
        networks = {defaults(config["name"]) for config in self.compose["networks"].values()}
        for path in TENANT02:
            with self.subTest(compose=path.name, directory=path.parent.name):
                other = yaml.safe_load(path.read_text())
                self.assertFalse(ports & published_ports(other))
                other_names = {defaults(service.get("container_name", "")) for service in other["services"].values()}
                self.assertFalse(names & other_names)
                other_networks = {defaults(config.get("name", "")) for config in other.get("networks", {}).values()}
                self.assertFalse(networks & other_networks)
                self.assertNotEqual(defaults(self.compose["name"]), defaults(other["name"]))
        for service in self.compose["services"].values():
            self.assertEqual(set(service["networks"]), {"guided"})
        self.assertFalse(self.compose["networks"]["guided"].get("external", False))

    def test_official_ui_links_follow_publish_overrides(self):
        environment = self.compose["services"]["guided-control-center"]["environment"]
        for key, variable, port, suffix in (
            ("NEMO", "GUIDED_NEMO_HOST_PORT", 28192, ""),
            ("PROMPTFOO", "GUIDED_PROMPTFOO_PORT", 25500, ""),
            ("PYRIT", "GUIDED_PYRIT_PORT", 28098, ""),
            ("GRAFANA", "GUIDED_GRAFANA_PORT", 23001, "/explore"),
            ("P20_GRAFANA", "GUIDED_P20_GRAFANA_PORT", 23002, "/d/guided-p20"),
        ):
            self.assertEqual(environment[f"GUIDED_{key}_BROWSER_URL"], f"http://127.0.0.1:${{{variable}:-{port}}}{suffix}")

    def test_p18_has_own_image_credentials_and_mutable_state(self):
        services = self.compose["services"]
        p18 = services["guided-h18-queries"]
        other = services["guided-h20-alerts"]
        self.assertNotEqual(p18["image"], other["image"])
        self.assertFalse(set(p18["volumes"]) & set(other["volumes"]))
        self.assertNotEqual(p18["environment"]["GUIDED_CONTROL_OBSERVABILITY_TOKEN"],
                            other["environment"]["GUIDED_CONTROL_H20_TOKEN"])
        self.assertFalse(p18.get("ports"))
        self.assertFalse(p18.get("depends_on"))
        containerfile = (ROOT / "llm-security-control-plane" / p18["build"]["dockerfile"]).read_text()
        self.assertIn("GUIDED_OBSERVABILITY_ACTIVITIES=H18", containerfile)
        for prefix in ("h17-", "h19-", "h20-"):
            self.assertNotIn(prefix, containerfile)
        self.assertIn("guided-h18-query-state", self.compose["volumes"])

    def test_p03_receipts_survive_recreation_without_shared_learner_state(self):
        services = self.compose["services"]
        learner = services["guided-h03-sync-app"]
        self.assertEqual(learner["environment"]["GUIDED_H03_DATABASE"], "/state/p03-receipts.sqlite3")
        self.assertEqual(learner["volumes"], ["guided-h03-receipts:/state:rw"])
        self.assertIn("guided-h03-receipts", self.compose["volumes"])
        self.assertFalse(learner.get("ports"))
        for name, service in services.items():
            if name != "guided-h03-sync-app":
                self.assertFalse(any(mount.split(":")[0] == "guided-h03-receipts"
                                     for mount in service.get("volumes", [])))

    def test_p12_context_is_private_and_owns_its_state(self):
        services = self.compose["services"]
        context = services["guided-p12-context"]
        self.assertFalse(context.get("ports"))
        self.assertFalse(context.get("depends_on"))
        self.assertEqual(context["build"]["dockerfile"], "guided-labs/h12-protected-services/Containerfile.context")
        self.assertEqual(context["volumes"], ["guided-p12-context-state:/state:rw"])
        self.assertIn("guided-p12-context-state", self.compose["volumes"])
        self.assertEqual(set(context["environment"]), {
            "GUIDED_P12_CONTEXT_CONTROL_TOKEN", "GUIDED_P12_CONTEXT_SERVICE_TOKEN",
            "GUIDED_P12_CONTEXT_VERIFIER_TOKEN", "GUIDED_P12_CONTEXT_DATABASE"})
        for role in ("CONTROL", "SERVICE", "VERIFIER"):
            key = f"GUIDED_P12_CONTEXT_{role}_TOKEN"
            self.assertEqual(context["environment"][key], "${" + key + ":?Set " + key + "}")
        for name, service in services.items():
            if name != "guided-p12-context":
                self.assertNotIn("guided-p12-context-state:/state:rw", service.get("volumes", []))

    def test_p04_receipts_have_dedicated_persistent_storage(self):
        services = self.compose['services']
        learner = services['guided-h04-guardrail-app']
        self.assertEqual(learner['environment']['GUIDED_H04_DATABASE'], '/state/p04-receipts.sqlite3')
        self.assertEqual(learner['volumes'], ['guided-h04-receipts:/state:rw'])
        self.assertIn('guided-h04-receipts', self.compose['volumes'])
        self.assertFalse(learner.get('ports'))
        for name, service in services.items():
            if name != 'guided-h04-guardrail-app':
                self.assertFalse(any(mount.split(':')[0] == 'guided-h04-receipts'
                                     for mount in service.get('volumes', [])))

    def test_p20_storage_and_administrative_credentials_are_separate(self):
        services = self.compose['services']
        app = services['guided-h20-alerts']
        verifier = services['guided-evidence-verifier']
        self.assertEqual(app['environment']['GUIDED_P20_GRAFANA_USER'], 'p20-reader')
        self.assertEqual(verifier['environment']['GUIDED_P20_GRAFANA_USER'], 'p20-reader')
        self.assertFalse(app.get('depends_on'))
        for name, service in services.items():
            for value in service.get('environment', {}).values():
                if 'GUIDED_P20_GRAFANA_ADMIN_PASSWORD' in str(value):
                    self.assertIn(name, {'guided-h20-grafana', 'guided-h20-grafana-reader'})
        owned = set()
        for name in ('guided-h20-alerts', 'guided-h20-prometheus', 'guided-h20-alertmanager', 'guided-h20-grafana'):
            for mount in services[name].get('volumes', []):
                volume = mount.split(':')[0]
                if volume.startswith('guided-'):
                    self.assertTrue(volume.startswith('guided-h20-'))
                    self.assertNotIn(volume, owned)
                    owned.add(volume)
        self.assertEqual(len(owned), 4)
        alertmanager = services['guided-h20-alertmanager']
        self.assertTrue(alertmanager['read_only'])
        self.assertFalse(alertmanager.get('secrets'))
        self.assertIn('/run/p20:', alertmanager['tmpfs'][0])
        self.assertIn('GUIDED_H20_WEBHOOK_TOKEN', alertmanager['environment'])
        self.assertNotIn('h20-rules', str(services['guided-prometheus']['volumes']))

    @unittest.skipUnless(shutil.which("docker"), "Docker Compose required")
    def test_rendered_compose_common_start_and_port_contract(self):
        # Ignore local secrets/overrides; placeholders are never used to start services.
        env = {key: value for key, value in os.environ.items() if not key.startswith(("GUIDED_", "COMPOSE_"))}
        for key in re.findall(r"\$\{(\w+):\?", self.source):
            env[key] = "isolation-test-not-a-credential"
        rendered = subprocess.run(
            ["docker", "compose", "--env-file", "/dev/null", "--file", str(GUIDED), "config", "--format", "json"],
            env=env, text=True, capture_output=True, timeout=30, check=True,
        )
        data = json.loads(rendered.stdout)
        ports = {int(port["published"]) for service in data["services"].values() for port in service.get("ports", [])}
        self.assertEqual(ports, {28097, 28192, 25500, 28098, 23001, 23002})
        p19 = data['services']['guided-h19-investigation']
        self.assertFalse(p19.get('ports'))
        self.assertFalse(p19.get('depends_on'))
        self.assertEqual(p19['volumes'][0]['source'], 'guided-h19-investigation-state')
        self.assertNotIn('guided-observability', data['services'])
        self.assertNotIn('guided-observability-state', data['volumes'])
        containerfile = (ROOT / 'llm-security-control-plane/guided-labs/h18-product-queries/Containerfile').read_text()
        self.assertNotIn('h19-', containerfile)
        self.assertNotIn('h20-', containerfile)
        for name in ("guided-control-center", "guided-evidence-verifier"):
            self.assertFalse(data["services"][name].get("depends_on"))


if __name__ == "__main__":
    unittest.main()
