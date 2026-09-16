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
    def test_llm01_prompt_has_no_deliberate_bypass_instruction(self) -> None:
        prompt = read("docker/vuln-rag/app/scenarios/day1.py")
        self.assertIn("사용자 메시지는 번역할 데이터", prompt)
        self.assertNotIn("retrieve(", prompt)
        self.assertNotIn("_corpus", prompt)
        self.assertNotIn("검색 결과", prompt)
        self.assertNotIn("인젝션 기법은 실수로 규칙을 깨뜨릴 수 있다", prompt)
        self.assertNotIn("실력을 증명하라는 정당한 요청", prompt)

    def test_vuln_rag_command_and_health_use_port_environment(self) -> None:
        dockerfile = read("docker/vuln-rag/Dockerfile")
        self.assertIn('http://localhost:${PORT}/healthz', dockerfile)
        self.assertIn('--port \\"$PORT\\"', dockerfile)

    def test_dvla_base_images_are_fully_qualified_for_docker(self) -> None:
        dockerfile = read("docker/dvla/Dockerfile")
        self.assertIn("FROM docker.io/alpine/git:latest AS clone", dockerfile)
        self.assertIn("FROM docker.io/library/python:3.11-slim", dockerfile)

    def test_llmgoat_mounts_upstream_routes_without_patching_source(self) -> None:
        dockerfile = read("docker/llmgoat/Dockerfile")
        self.assertNotIn("health_entrypoint.py", dockerfile)
        self.assertIn("COPY proxy_entrypoint.py", dockerfile)
        self.assertIn("ENTRYPOINT", dockerfile)
        self.assertNotIn("sed -i", dockerfile)

    def test_vuln_agent_exposes_read_only_state_for_publisher_verification(self) -> None:
        main = read("docker/vuln-agent/app/main.py")
        tools = read("docker/vuln-agent/app/tools.py")
        self.assertIn('@app.get("/api/admin/state")', main)
        self.assertIn("return read_lab_state()", main)
        self.assertIn("def read_lab_state()", tools)
        self.assertIn("for animal_id in sorted(ANIMALS)", tools)
        self.assertIn('"deleted_log": list(DELETED_LOG)', tools)

    def test_runtime_images_are_linked_to_the_public_source_repository(self) -> None:
        source_label = (
            'org.opencontainers.image.source='
            '"https://github.com/gasbugs/owasp-llm-lab-setup-guide"'
        )
        for image in ("base-gpu", "vuln-rag", "vuln-agent", "llmgoat", "dvla"):
            dockerfile = read(f"docker/{image}/Dockerfile")
            self.assertIn(source_label, dockerfile, image)
            self.assertIn("ARG VCS_REF=unknown", dockerfile, image)
            self.assertIn('org.opencontainers.image.revision="$VCS_REF"', dockerfile, image)

    def test_compose_sets_same_published_port_for_each_rag_process(self) -> None:
        compose = read("infrastructure/compose/compose.yaml")
        runner = read("infrastructure/scripts/student/recreate-editable-lab")
        for port in (8000, 8010, 8011, 8012, 8013):
            self.assertIn(f'"{port}:{port}"', compose)
            self.assertIn(f'"--port", "{port}"', compose)
        self.assertIn('docker compose up -d --no-deps --force-recreate "$service"', runner)

    def test_ollama_compat_alias_is_verified_after_transient_cli_eof(self) -> None:
        installer = read("infrastructure/scripts/student/install-lab.sh")
        self.assertIn(
            'ollama create "$OLLAMA_COMPAT_MODEL" -f /tmp/Modelfile.compat || true',
            installer,
        )
        self.assertIn(
            'ollama show "$OLLAMA_COMPAT_MODEL" >/dev/null 2>&1',
            installer,
        )
        self.assertIn(
            'compatibility alias is absent after create: $OLLAMA_COMPAT_MODEL',
            installer,
        )

    def test_every_deployed_service_has_an_explicit_port_exposure_contract(self) -> None:
        installer = read("infrastructure/scripts/student/install-lab.sh")
        compose = read("infrastructure/compose/compose.yaml")
        published_services = {
            "lab-reverse-proxy": 80,
            "lab-prompt-rag": 8000,
            "lab-data-rag": 8010,
            "lab-output-rag": 8011,
            "lab-knowledge-rag": 8012,
            "lab-resource-rag": 8013,
            "lab-vuln-agent": 8001,
            "lab-ollama": 11434,
            "lab-llmgoat": 5000,
            "lab-fake-registry": 8002,
            "lab-portal": 8080,
        }
        health_urls = {
            "lab-ollama": "http://localhost:11434/api/tags",
            "lab-prompt-rag": "http://localhost:8000/healthz",
            "lab-data-rag": "http://localhost:8010/healthz",
            "lab-output-rag": "http://localhost:8011/healthz",
            "lab-knowledge-rag": "http://localhost:8012/healthz",
            "lab-resource-rag": "http://localhost:8013/healthz",
            "lab-vuln-agent": "http://localhost:8001/healthz",
            "lab-llmgoat": "http://localhost:5000/api/model_status",
            "lab-dvla": "http://localhost:8501/_stcore/health",
            "lab-fake-registry": "http://localhost:8002/api/v1/models",
            "lab-portal": "http://localhost:8080/",
        }
        for service, port in published_services.items():
            self.assertIn(f"[{service}]={port}", installer)
            self.assertIn(f'"{port}:{port}"', compose)
        for service, url in health_urls.items():
            with self.subTest(service=service):
                self.assertIn(url, installer)
        self.assertIn('docker port lab-reverse-proxy 8501/tcp', installer)
        self.assertIn('"8501:8501"', compose)
        dvla_service = compose.split("\n  dvla:", 1)[1].split(
            "\n  fake-registry:", 1
        )[0]
        self.assertNotIn("\n    ports:", dvla_service)
        self.assertIn('network_mode=$(docker inspect', installer)
        self.assertIn('[ "$network_mode" = "host" ]', installer)
        self.assertIn('published=$(docker port', installer)
        self.assertIn('has no published host port', installer)
        self.assertNotIn("network_mode: host", compose)

    def test_compose_container_names_are_role_based_without_dates(self) -> None:
        installer = read("infrastructure/scripts/student/install-lab.sh")
        compose = read("infrastructure/compose/compose.yaml")
        runner = read("infrastructure/scripts/student/recreate-editable-lab")
        for unit in (
            "lab-prompt-rag",
            "lab-data-rag",
            "lab-output-rag",
            "lab-knowledge-rag",
            "lab-resource-rag",
            "lab-vuln-agent",
        ):
            self.assertIn(f"  {unit})", runner)
        for unit in ("lab-dvla", "lab-fake-registry"):
            self.assertIn(f"container_name: {unit}", compose)

        self.assertNotIn("container_name: lab-day", compose)

    def test_secure_coding_uses_container_layer_and_docker_recreation(self) -> None:
        installer = read("infrastructure/scripts/student/install-lab.sh")
        runner = read("infrastructure/scripts/student/recreate-editable-lab")
        workflow = read(".github/workflows/build-and-push.yaml")
        self.assertNotIn("seed_editable_tree()", installer)
        self.assertNotIn("RUNTIME_SOURCE_ROOT=", installer)
        self.assertNotIn("runtime-src/${rag_unit}/app:/app/app", installer)
        self.assertNotIn("runtime-src/lab-vuln-agent/app:/app/app", installer)
        self.assertIn("--force-recreate", runner)
        self.assertIn("http://ollama:11434", read("infrastructure/compose/compose.yaml"))
        self.assertIn(
            'container_layer_source_files=(',
            installer,
        )
        self.assertIn(
            '[lab-prompt-rag]="/app/app/secure_coding.py"',
            installer,
        )
        self.assertIn(
            '[lab-vuln-agent]="/app/app/main.py"',
            installer,
        )
        self.assertIn(
            'docker exec "$container" test -w "$source_file"',
            installer,
        )
        self.assertIn(
            'grep -qx \'/app/app\'',
            installer,
        )
        self.assertIn(
            "docker/ infrastructure/compose/ infrastructure/scripts/student/install-lab.sh",
            workflow,
        )

    def test_installer_requires_explicit_asg_cleanup_without_lambda(self) -> None:
        installer = read("infrastructure/scripts/student/install-lab.sh")
        self.assertIn("자동 중지 Lambda·EventBridge를 만들지 않습니다", installer)
        self.assertIn("stop-lab.sh로 ASG를 0으로 낮추면", installer)

    def test_user_data_bootstrap_reuses_pinned_runtime_installer(self) -> None:
        instance = read("infrastructure/terraform/instance.tf")
        template = read("infrastructure/terraform/user-data.sh.tpl")
        self.assertIn(
            "user_data     = var.enable_user_data_bootstrap ? base64encode(local.user_data) : null",
            instance,
        )
        self.assertIn(
            'curl -fsSL "$RAW_URL/infrastructure/scripts/student/install-lab.sh"',
            template,
        )
        self.assertIn('IMAGE_TAG="$IMAGE_TAG"', template)
        self.assertIn('LAB_SETUP_REPO_RAW_URL="$RAW_URL"', template)
        self.assertIn(
            "local.lab_setup_source_revision == trimprefix(var.lab_image_tag, \"sha-\")",
            instance,
        )

    def test_reinstall_reconciles_images_units_and_downloaded_source(self) -> None:
        installer = read("infrastructure/scripts/student/install-lab.sh")
        self.assertIn('curl -fsSL "$RAW_URL/infrastructure/fake-registry/server.py"', installer)
        self.assertIn('FAKE_REGISTRY_CHANGED=true', installer)
        self.assertIn('curl -fsSL "$RAW_URL/infrastructure/compose/compose.yaml"', installer)
        self.assertIn("docker compose config", installer)
        self.assertIn("docker compose up -d", installer)
        self.assertIn('[ "$REFRESH_IMAGES" = "true" ]', installer)
        self.assertIn('LAB_ENV_CANDIDATE=/etc/lab/env.pending', installer)
        self.assertIn('mv -f "$LAB_ENV_CANDIDATE" /etc/lab/env', installer)
        self.assertIn("verifying reconciled service health", installer)
        self.assertIn("docker image inspect --format '{{.Id}}'", installer)
        self.assertIn("WARMUP_RESPONSE=", installer)
        self.assertIn(".done == true", installer)
        self.assertIn(
            '"$RAW_URL/infrastructure/scripts/student/reset-lab"', installer
        )
        self.assertIn(
            "install -m 0755 -o root -g root "
            '"$RESET_LAB_CANDIDATE" /usr/local/bin/reset-lab',
            installer,
        )
        self.assertIn("http://localhost:5000/api/model_status", installer)
        internal_health = installer.index(
            "docker exec lab-llmgoat \\\n"
            "    curl -fsS --max-time 5 http://127.0.0.1:5000/api/model_status"
        )
        publish_refresh = installer.index(
            "docker restart lab-llmgoat", internal_health
        )
        external_health = installer.index(
            "http://localhost:5000/api/model_status", publish_refresh
        )
        self.assertLess(internal_health, publish_refresh)
        self.assertLess(publish_refresh, external_health)
        self.assertNotIn("LLAMA_GUARD_MODEL", installer)
        self.assertNotIn("llama-guard3:8b", installer)

    def test_installer_waits_for_fresh_ami_package_manager_lock(self) -> None:
        installer = read("infrastructure/scripts/student/install-lab.sh")
        self.assertIn('APT_LOCK_TIMEOUT_SECONDS="${APT_LOCK_TIMEOUT_SECONDS:-600}"', installer)
        self.assertIn(
            'apt-get -o "DPkg::Lock::Timeout=$APT_LOCK_TIMEOUT_SECONDS" update -y',
            installer,
        )
        self.assertIn(
            'apt-get -o "DPkg::Lock::Timeout=$APT_LOCK_TIMEOUT_SECONDS" \\\n'
            "    install -y --no-install-recommends",
            installer,
        )
        self.assertIn(
            "APT_LOCK_TIMEOUT_SECONDS must be a non-negative integer", installer
        )

    def test_single_compose_definition_is_canonical(self) -> None:
        self.assertTrue((ROOT / "infrastructure" / "compose" / "compose.yaml").exists())
        self.assertFalse((ROOT / "docker" / "docker-compose.yaml").exists())

    def test_security_group_defaults_to_loopback_only(self) -> None:
        terraform = read("infrastructure/terraform/main.tf")
        self.assertNotIn("lab_app_ports", terraform)
        self.assertNotIn("module08_observability_ports", terraform)
        network = read("infrastructure/terraform/network.tf")
        self.assertIn("cidr_blocks = [var.allowed_ingress_cidr]", network)
        self.assertIn('protocol    = "-1"', network)
        self.assertNotIn('dynamic "ingress"', network)
        self.assertEqual(network.count("  ingress {"), 1)
        variables = read("infrastructure/terraform/variables.tf")
        self.assertIn("[0-9]{1,3}/32", variables)
        self.assertIn('default     = "127.0.0.1/32"', variables)
        self.assertNotIn('var.allowed_ingress_cidr != "127.0.0.1/32"', variables)

    def test_provider_default_tags_are_plan_time_known(self) -> None:
        terraform = read("infrastructure/terraform/main.tf")
        provider_tags = terraform.split("provider_default_tags = {", 1)[1].split("}", 1)[0]
        self.assertIn("tags = local.provider_default_tags", terraform)
        self.assertNotIn("random_", provider_tags)
        self.assertNotIn("Deployment", provider_tags)

    def test_new_instances_use_latest_matching_ami_without_id_pin(self) -> None:
        instance = read("infrastructure/terraform/instance.tf")
        variables = read("infrastructure/terraform/variables.tf")
        packer = read("infrastructure/packer/ami.pkr.hcl")
        quickstart = read("docs/STUDENT-QUICKSTART.md")

        terraform_ami = instance.split('data "aws_ami" "lab_base"', 1)[1].split(
            'resource "aws_launch_template" "student"', 1
        )[0]
        self.assertIn("most_recent = true", terraform_ami)
        self.assertIn("owners      = [var.ami_owner_id]", terraform_ami)
        self.assertIn("values = [var.ami_name_pattern]", terraform_ami)
        self.assertIn("image_id      = data.aws_ami.lab_base.id", instance)
        self.assertIn("create_before_destroy = true", instance)
        self.assertNotRegex(instance, r'(?m)^\s*ami\s*=\s*"ami-[0-9a-f]+"')
        self.assertNotIn('variable "ami_id"', variables)
        self.assertNotIn('variable "golden_ami_id"', variables)
        for path in (ROOT / "infrastructure").rglob("*"):
            if path.is_file() and path.suffix in {".tf", ".hcl"}:
                self.assertNotRegex(path.read_text(encoding="utf-8"), r"ami-[0-9a-f]{8,}")

        packer_source = packer.split('data "amazon-ami" "ubuntu"', 1)[1].split(
            'source "amazon-ebs" "lab"', 1
        )[0]
        self.assertIn("most_recent = true", packer_source)
        self.assertIn("source_ami      = data.amazon-ami.ubuntu.id", packer)
        self.assertNotIn('variable "source_ami_id"', packer)
        self.assertIn("AMI ID는 직접 입력하지 않습니다.", quickstart)

    def test_build_is_gated_and_latest_is_promoted_after_sha_set(self) -> None:
        workflow = read(".github/workflows/build-and-push.yaml")
        test_job = workflow.split("  test:\n", 1)[1].split("  build:\n", 1)[0]
        build = workflow.split("  build:\n", 1)[1].split("  promote-latest:\n", 1)[0]
        promote = workflow.split("  promote-latest:\n", 1)[1]
        self.assertIn("hashicorp/setup-packer@v3.4.0", test_job)
        self.assertIn("hashicorp/setup-terraform@v4", test_job)
        self.assertIn("docker/build-push-action@v7", test_job)
        self.assertIn("packer validate -syntax-only", test_job)
        self.assertIn("find infrastructure tests docker", test_job)
        self.assertEqual(test_job.count("call: check"), 5)
        self.assertNotIn("packages: write", test_job)
        self.assertIn("needs: test", build)
        self.assertIn("IMAGE_REGISTRY: ghcr.io", workflow)
        self.assertIn("IMAGE_NAMESPACE: gasbugs", workflow)
        self.assertIn("packages: write", build)
        self.assertIn("username: ${{ github.actor }}", build)
        self.assertIn("password: ${{ secrets.GITHUB_TOKEN }}", build)
        self.assertNotIn("DOCKERHUB_USERNAME", workflow)
        self.assertNotIn("DOCKERHUB_TOKEN", workflow)
        self.assertIn("${{ env.SHA_TAG }}", build)
        self.assertNotIn(":latest", build)
        self.assertIn("Refuse to overwrite an existing commit tag", build)
        self.assertIn("https://ghcr.io/token", build)
        self.assertIn('case "$status" in', build)
        self.assertIn("confirmed absent", build)
        self.assertIn("VCS_REF=${{ github.sha }}", build)
        self.assertNotIn("docker buildx imagetools inspect", build)
        self.assertIn("needs: build", promote)
        self.assertIn("packages: write", promote)
        self.assertIn(":latest", promote)
        self.assertIn(
            "python tests/e2e/llm08/test_llm08_shared_corpus.py", workflow
        )

        runner = read("tests/e2e/run-all.sh")
        self.assertIn('"$SCRIPT_DIR/$item"/test_*.py', runner)
        self.assertIn('*.py) runner=(python3 "$s")', runner)

    def test_packer_requires_the_same_image_tag(self) -> None:
        packer = read("infrastructure/packer/ami.pkr.hcl")
        provisioner = read("infrastructure/packer/provisioners/40-pull-images.sh")
        self.assertIn('variable "image_tag"', packer)
        self.assertIn('variable "image_namespace"', packer)
        legacy_namespace = "docker" + "hub_namespace"
        self.assertNotIn(f'variable "{legacy_namespace}"', packer)
        self.assertIn('"IMAGE_NAMESPACE=${var.image_namespace}"', packer)
        self.assertIn('"IMAGE_TAG=${var.image_tag}"', packer)
        self.assertIn('^sha-[0-9a-f]{40}$', packer)
        self.assertIn("ghcr.io/${IMAGE_NAMESPACE}/", provisioner)
        self.assertIn("owasp-llm-${image}:${IMAGE_TAG}", provisioner)

    def test_user_data_propagates_the_selected_runtime_image_set(self) -> None:
        variables = read("infrastructure/terraform/variables.tf")
        instance = read("infrastructure/terraform/instance.tf")
        user_data = read("infrastructure/terraform/user-data.sh.tpl")
        example = read("infrastructure/terraform/terraform.tfvars.example")
        advanced = read("docs/TERRAFORM-ADVANCED-OPTIONS.md")

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
        self.assertIn("ghcr.io/$IMAGE_NAMESPACE/", user_data)
        self.assertNotIn("lab_setup_repo_raw_url", example)
        self.assertNotIn("lab_image_tag", example)
        self.assertIn("lab_setup_repo_raw_url", advanced)
        self.assertIn("lab_image_tag", advanced)
        self.assertIn("user-data를 다시 실행하지 않는다", advanced)
        self.assertIn("lab_setup_source_revision", instance)
        self.assertIn('trimprefix(var.lab_image_tag, "sha-")', instance)
        self.assertIn("commit-pinned bootstrap", instance)

    def test_terraform_inputs_match_the_one_account_model(self) -> None:
        variables = read("infrastructure/terraform/variables.tf")
        terraform = read("infrastructure/terraform/main.tf")
        example = read("infrastructure/terraform/terraform.tfvars.example")
        terraform_dir = ROOT / "infrastructure" / "terraform"
        all_terraform = "\n".join(
            path.read_text(encoding="utf-8") for path in terraform_dir.glob("*.tf")
        )

        self.assertNotIn('variable "student_id"', variables)
        self.assertNotIn('variable "student_ids"', variables)
        self.assertNotIn("student_ids", terraform)
        self.assertNotIn('variable "course_start_date"', variables)
        self.assertNotIn('variable "course_dates"', variables)
        self.assertNotIn('variable "monthly_budget_usd"', variables)
        self.assertNotIn('variable "course_budget_usd"', variables)
        self.assertNotIn('variable "daily_budget_usd"', variables)
        self.assertNotIn('variable "alert_email"', variables)
        self.assertFalse((terraform_dir / "budgets.tf").exists())
        self.assertNotIn("aws_budgets_budget", all_terraform)
        self.assertNotIn("aws_sns_topic", all_terraform)
        self.assertIn("enable_user_data_bootstrap = false", example)
        self.assertLessEqual(len(example.splitlines()), 20)

    def test_teardown_lists_and_verifies_the_complete_state(self) -> None:
        teardown = read("infrastructure/scripts/instructor/teardown-day.sh")
        stop = read("infrastructure/scripts/student/stop-lab.sh")

        self.assertNotIn("head -20", teardown)
        self.assertNotIn("state list 2>/dev/null", teardown)
        self.assertIn("CURRENT_STATE=$(terraform state list)", teardown)
        self.assertIn("REMAINING_STATE=$(terraform state list)", teardown)
        self.assertIn('if [ -n "$REMAINING_STATE" ]', teardown)
        self.assertNotIn("비용 0/h", teardown)
        self.assertIn("root EBS가 삭제됩니다", stop)
        self.assertIn("가용 용량이 있는 AZ에 새 인스턴스가 생성", stop)

    def test_terraform_omits_lambda_and_eventbridge_auto_stop(self) -> None:
        variables = read("infrastructure/terraform/variables.tf")
        versions = read("infrastructure/terraform/versions.tf")
        instance = read("infrastructure/terraform/instance.tf")
        outputs = read("infrastructure/terraform/outputs.tf")

        self.assertFalse((ROOT / "infrastructure/terraform/auto_stop.tf").exists())
        self.assertFalse((ROOT / "infrastructure/terraform/lambda/auto_stop.py").exists())
        self.assertNotIn('source  = "hashicorp/archive"', versions)
        self.assertNotIn('variable "enable_auto_stop"', variables)
        self.assertNotIn("aws_cloudwatch_event_target", instance)
        self.assertNotIn('output "auto_stop_schedule"', outputs)

    def test_asg_uses_all_supported_gpu_zones_and_scales_to_zero(self) -> None:
        network = read("infrastructure/terraform/network.tf")
        instance = read("infrastructure/terraform/instance.tf")
        outputs = read("infrastructure/terraform/outputs.tf")

        self.assertIn('data "aws_ec2_instance_type_offerings" "gpu"', network)
        self.assertIn("selected_availability_zones", network)
        self.assertIn('resource "aws_autoscaling_group" "student"', instance)
        self.assertRegex(
            instance,
            r"vpc_zone_identifier\s+= values\(aws_subnet\.lab\)\[\*\]\.id",
        )
        self.assertRegex(instance, r"desired_capacity\s+= 1")
        self.assertIn("ignore_failed_scaling_activities = true", instance)
        self.assertIn("ignore_changes = [desired_capacity]", instance)
        self.assertIn("--desired-capacity 0", outputs)

    def test_local_build_helper_rejects_implicit_moving_tags(self) -> None:
        script = ROOT / "docker" / "build-and-push.sh"
        env = os.environ.copy()
        env["IMAGE_NAMESPACE"] = "example"
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

        source = script.read_text(encoding="utf-8")
        self.assertIn('case "$inspect_text" in', source)
        self.assertIn('VCS_REF=${TAG#sha-}', source)
        self.assertNotIn('manifest inspect "$image" >/dev/null 2>&1', source)

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
        self.assertIn("restart_llm10_stack_after_overload", llm10)
        self.assertIn('"$reset_script" llm10', llm10)
        self.assertIn("R1-reset-lab.txt", llm10)
        self.assertNotIn("docker", llm10)
        self.assertIn('trap recover_parallel_probe_on_exit EXIT', llm10)
        self.assertIn('warmup_model recovery', llm10)
        self.assertIn(
            'for attempt in $(seq 1 "$WARMUP_ATTEMPTS")', llm10
        )
        self.assertIn(
            '--max-time "$WARMUP_REQUEST_TIMEOUT_SECONDS"', llm10
        )
        self.assertGreaterEqual(llm10.count("warmup_model"), 3)

    def test_mutating_e2e_is_repeatable_and_infra_fails_closed(self) -> None:
        common = read("tests/e2e/lib/common.sh")
        self.assertIn("delete_docs_by_title", common)
        self.assertIn("infra_fail", common)
        self.assertIn('return 3', common)

        script = read("tests/e2e/llm08/test_llm08_rag_poisoning.sh")
        self.assertIn("trap cleanup EXIT", script)
        self.assertIn("delete_docs_by_title", script)

        llm01 = read("tests/e2e/llm01/test_llm01_no_rag.sh")
        self.assertIn('has("retrieved_chunks") | not', llm01)
        self.assertIn('RAG is not enabled for LLM01', llm01)

        agent = read("tests/e2e/llm06/test_llm06_agency.sh")
        self.assertIn('/api/admin/state', agent)
        self.assertIn('"$reset_script" llm06', agent)
        self.assertIn("A4-state-after-request.json", agent)
        self.assertIn("A4-state-after-reset.json", agent)
        self.assertNotIn('/api/admin/reset', agent)
        self.assertIn("trap cleanup EXIT", agent)

        full_cycle = read("tests/e2e/run-full-cycle.sh")
        self.assertIn("reset_mutable_state", full_cycle)
        self.assertIn("BASELINE_DOC_COUNTS", full_cycle)
        self.assertIn("E2E_RESET_SENTINEL_", full_cycle)
        self.assertIn('"$recreate_editable_lab" "$container"', full_cycle)
        self.assertIn('"$recreate_editable_lab" lab-vuln-agent', full_cycle)
        self.assertIn('/api/admin/state', full_cycle)
        self.assertNotIn("docker restart", full_cycle)
        self.assertNotIn('/api/admin/reset', full_cycle)
        self.assertIn('(.docs | length == $expected)', full_cycle)
        self.assertIn("contains($sentinel)", full_cycle)
        self.assertNotIn(".docs | length == 0", full_cycle)
        self.assertLess(full_cycle.index("run_agent\n"), full_cycle.index("run_items day5"))

    def test_llm03_cosign_mount_is_traversable_by_non_root_container(self) -> None:
        supply_chain = read("tests/e2e/llm03/test_llm03_supply_chain.sh")
        self.assertIn('TMPDIR=$(mktemp -d)', supply_chain)
        self.assertIn('chmod 0755 "$TMPDIR"', supply_chain)
        self.assertIn('-v "$TMPDIR:/work:ro"', supply_chain)
        self.assertNotIn("A.gguf.key", supply_chain)


if __name__ == "__main__":
    unittest.main()
