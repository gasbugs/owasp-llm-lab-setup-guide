from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class WorkflowActionRuntimeTests(unittest.TestCase):
    def test_workflows_do_not_pin_node20_action_majors(self) -> None:
        forbidden = {
            "actions/checkout@v4",
            "actions/setup-python@v5",
            "docker/build-push-action@v6",
            "docker/login-action@v3",
            "docker/setup-buildx-action@v3",
            "hashicorp/setup-packer@v3.2.0",
            "hashicorp/setup-terraform@v3",
        }
        findings: list[str] = []
        for path in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
            text = path.read_text(encoding="utf-8")
            for action in forbidden:
                if action in text:
                    findings.append(f"{path.name}: {action}")
        self.assertEqual(findings, [])

    def test_only_runtime_or_installer_changes_publish_images(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "build-and-push.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("needs.test.outputs.runtime_changed == 'true'", workflow)
        self.assertIn(
            'git diff --quiet "$BEFORE_SHA" "$CURRENT_SHA" -- \\',
            workflow,
        )
        self.assertIn(
            "docker/ infrastructure/compose/ infrastructure/scripts/student/install-lab.sh",
            workflow,
        )
        self.assertIn("fetch-depth: 0", workflow)


if __name__ == "__main__":
    unittest.main()
