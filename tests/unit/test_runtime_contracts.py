"""Static regression tests for the canonical fixed-port runtime contract."""
from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class RuntimeContractTest(unittest.TestCase):
    def test_vuln_rag_command_and_health_use_port_environment(self) -> None:
        dockerfile = read("docker/vuln-rag/Dockerfile")
        self.assertIn('http://localhost:${PORT}/healthz', dockerfile)
        self.assertIn('--port \\"$PORT\\"', dockerfile)

    def test_dvla_base_images_are_fully_qualified_for_podman(self) -> None:
        dockerfile = read("docker/dvla/Dockerfile")
        self.assertIn("FROM docker.io/alpine/git:latest AS clone", dockerfile)
        self.assertIn("FROM docker.io/library/python:3.11-slim", dockerfile)

    def test_quadlet_sets_same_port_for_each_rag_process(self) -> None:
        installer = read("infrastructure/scripts/student/install-lab.sh")
        self.assertIn("Environment=PORT=${rag_port}", installer)
        self.assertIn("--port ${rag_port}", installer)

    def test_reinstall_reconciles_images_units_and_downloaded_source(self) -> None:
        installer = read("infrastructure/scripts/student/install-lab.sh")
        self.assertIn('curl -fsSL "$RAW_URL/infrastructure/fake-registry/server.py"', installer)
        self.assertIn('FAKE_REGISTRY_CHANGED=true', installer)
        self.assertIn('QUADLET_FINGERPRINT_BEFORE=', installer)
        self.assertIn('QUADLET_FINGERPRINT_AFTER=', installer)
        self.assertIn('[ "$REFRESH_IMAGES" = "true" ]', installer)
        self.assertIn('systemctl --user restart "$unit.service"', installer)
        self.assertIn('LAB_ENV_CANDIDATE=/etc/lab/env.pending', installer)
        self.assertIn('mv -f "$LAB_ENV_CANDIDATE" /etc/lab/env', installer)
        self.assertIn("verifying reconciled service health", installer)
        self.assertIn("podman image inspect --format '{{.Id}}'", installer)
        self.assertIn("WARMUP_RESPONSE=", installer)
        self.assertIn(".done == true", installer)

        fingerprint_before = installer.split(
            "QUADLET_FINGERPRINT_BEFORE=$(", 1
        )[1].split("\n)", 1)[0]
        self.assertIn('if [ -f "$file" ]; then', fingerprint_before)
        self.assertNotIn('[ -f "$file" ] &&', fingerprint_before)

    def test_legacy_compose_is_absent(self) -> None:
        self.assertFalse((ROOT / "docker" / "docker-compose.yaml").exists())

    def test_security_group_only_lists_deployed_app_ports(self) -> None:
        terraform = read("infrastructure/terraform/main.tf")
        self.assertIn(
            "toset([8000, 8001, 8002, 8010, 8011, 8012, 8013])",
            terraform,
        )
        self.assertNotIn("5050", read("infrastructure/terraform/network.tf"))
        self.assertIn(
            "[0-9]{1,3}/32", read("infrastructure/terraform/variables.tf")
        )

    def test_build_is_gated_and_latest_is_promoted_after_sha_set(self) -> None:
        workflow = read(".github/workflows/build-and-push.yaml")
        test_job = workflow.split("  test:\n", 1)[1].split("  build:\n", 1)[0]
        build = workflow.split("  build:\n", 1)[1].split("  promote-latest:\n", 1)[0]
        promote = workflow.split("  promote-latest:\n", 1)[1]
        self.assertIn("hashicorp/setup-packer@v3.2.0", test_job)
        self.assertIn("packer validate -syntax-only", test_job)
        self.assertIn("find infrastructure tests docker", test_job)
        self.assertEqual(test_job.count("call: check"), 5)
        self.assertIn("needs: test", build)
        self.assertIn("${{ env.SHA_TAG }}", build)
        self.assertNotIn(":latest", build)
        self.assertIn("Refuse to overwrite an existing commit tag", build)
        self.assertIn("docker buildx imagetools inspect", build)
        self.assertIn("needs: build", promote)
        self.assertIn(":latest", promote)
        self.assertIn(
            "python tests/e2e/llm04/test_llm04_shared_corpus.py", workflow
        )

        runner = read("tests/e2e/run-all.sh")
        self.assertIn('"$SCRIPT_DIR/$item"/test_*.py', runner)
        self.assertIn('*.py) runner=(python3 "$s")', runner)

    def test_packer_requires_the_same_image_tag(self) -> None:
        packer = read("infrastructure/packer/ami.pkr.hcl")
        provisioner = read("infrastructure/packer/provisioners/40-pull-images.sh")
        self.assertIn('variable "image_tag"', packer)
        self.assertIn('"IMAGE_TAG=${var.image_tag}"', packer)
        self.assertIn('^sha-[0-9a-f]{40}$', packer)
        self.assertIn("owasp-llm-${image}:${IMAGE_TAG}", provisioner)

    def test_user_data_propagates_the_selected_runtime_image_set(self) -> None:
        variables = read("infrastructure/terraform/variables.tf")
        instance = read("infrastructure/terraform/instance.tf")
        user_data = read("infrastructure/terraform/user-data.sh.tpl")
        example = read("infrastructure/terraform/terraform.tfvars.example")

        namespace = variables.split('variable "lab_image_namespace"', 1)[1].split(
            'variable "lab_image_tag"', 1
        )[0]
        image_tag = variables.split('variable "lab_image_tag"', 1)[1].split(
            'variable "ami_name_pattern"', 1
        )[0]
        self.assertIn('default     = "gasbugs"', namespace)
        self.assertIn('default     = "latest"', image_tag)
        self.assertIn('^sha-[0-9a-f]{40}$', image_tag)
        self.assertIn("lab_image_namespace    = var.lab_image_namespace", instance)
        self.assertIn("lab_image_tag          = var.lab_image_tag", instance)
        self.assertIn('IMAGE_NAMESPACE="${lab_image_namespace}"', user_data)
        self.assertIn('IMAGE_TAG="${lab_image_tag}"', user_data)
        self.assertIn('IMAGE_NAMESPACE="$IMAGE_NAMESPACE"', user_data)
        self.assertIn('IMAGE_TAG="$IMAGE_TAG"', user_data)
        self.assertIn("lab_setup_repo_raw_url", example)
        self.assertIn("lab_image_tag", example)
        self.assertIn("user_data_replace_on_change=false", example)
        self.assertIn("lab_setup_source_revision", instance)
        self.assertIn('trimprefix(var.lab_image_tag, "sha-")', instance)
        self.assertIn("commit-pinned bootstrap", instance)

    def test_teardown_lists_and_verifies_the_complete_state(self) -> None:
        teardown = read("infrastructure/scripts/instructor/teardown-day.sh")
        stop = read("infrastructure/scripts/student/stop-lab.sh")

        self.assertNotIn("head -20", teardown)
        self.assertNotIn("state list 2>/dev/null", teardown)
        self.assertIn("CURRENT_STATE=$(terraform state list)", teardown)
        self.assertIn("REMAINING_STATE=$(terraform state list)", teardown)
        self.assertIn('if [ -n "$REMAINING_STATE" ]', teardown)
        self.assertNotIn("비용 0/h", teardown)
        self.assertIn("이 구성은 EIP를 만들지 않아 public IP는 바뀔 수 있음", stop)
        self.assertIn("이 구성은 EIP를 만들지 않으므로 stop/start 후 public IP는 바뀔 수 있습니다", stop)

    def test_local_build_helper_rejects_implicit_moving_tags(self) -> None:
        script = ROOT / "docker" / "build-and-push.sh"
        env = os.environ.copy()
        env["DOCKERHUB_NAMESPACE"] = "example"
        env.pop("TAG", None)
        missing = subprocess.run(
            ["bash", str(script)], env=env, text=True, capture_output=True, check=False
        )
        self.assertNotEqual(missing.returncode, 0)

        env["TAG"] = "latest"
        moving = subprocess.run(
            ["bash", str(script)], env=env, text=True, capture_output=True, check=False
        )
        self.assertEqual(moving.returncode, 2)

    def test_e2e_urls_are_bounded_and_dynamic_reference_fetch_is_allowlisted(self) -> None:
        common = read("tests/e2e/lib/common.sh")
        self.assertIn('require_loopback_url "$TARGET_URL"', common)
        self.assertIn('require_loopback_url "$AGENT_URL"', common)

        for script in (ROOT / "tests" / "e2e").rglob("*.sh"):
            for number, line in enumerate(script.read_text(encoding="utf-8").splitlines(), 1):
                if "curl " in line and not line.lstrip().startswith("#"):
                    self.assertIn(
                        "--max-time",
                        line,
                        f"unbounded curl at {script.relative_to(ROOT)}:{number}",
                    )

        llm09 = read("tests/e2e/llm09/test_llm09_misinfo.sh")
        self.assertIn("is_allowed_aws_reference", llm09)
        self.assertIn("https://docs.aws.amazon.com", llm09)
        self.assertIn('missing_url_trials: $missing', llm09)
        self.assertIn("head -5 || true", llm09)
        self.assertIn("head -10 || true", llm09)

        llm10 = read("tests/e2e/llm10/test_llm10_consumption.sh")
        self.assertIn("transport_timeouts: $transport", llm10)
        self.assertIn('if [ "$observed" -ne 100 ]', llm10)
        self.assertIn("restart_ollama_after_overload", llm10)
        self.assertIn("overload queue cleanup: Ollama READY", llm10)
        self.assertGreaterEqual(llm10.count("warmup_model"), 3)

    def test_mutating_e2e_is_repeatable_and_infra_fails_closed(self) -> None:
        common = read("tests/e2e/lib/common.sh")
        self.assertIn("delete_docs_by_title", common)
        self.assertIn("infra_fail", common)
        self.assertIn('return 3', common)

        for relative in (
            "tests/e2e/llm01/test_llm01b_indirect.sh",
            "tests/e2e/llm04/test_llm04_poisoning.sh",
        ):
            script = read(relative)
            self.assertIn("trap cleanup EXIT", script)
            self.assertIn("delete_docs_by_title", script)

        agent = read("tests/e2e/llm06/test_llm06_agency.sh")
        self.assertIn('/api/admin/reset', agent)
        self.assertIn("trap cleanup EXIT", agent)

        full_cycle = read("tests/e2e/run-full-cycle.sh")
        self.assertIn("reset_mutable_state", full_cycle)
        self.assertIn("BASELINE_DOC_COUNTS", full_cycle)
        self.assertIn("E2E_RESET_SENTINEL_", full_cycle)
        self.assertIn('(.docs | length == $expected)', full_cycle)
        self.assertIn("contains($sentinel)", full_cycle)
        self.assertNotIn(".docs | length == 0", full_cycle)
        self.assertLess(full_cycle.index("run_agent\n"), full_cycle.index("run_items day5"))


if __name__ == "__main__":
    unittest.main()
