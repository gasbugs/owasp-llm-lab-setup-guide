"""Offline contracts for the cost-bounded instructor live-validation runner."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import time
import unittest
import urllib.error
from email.message import Message
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTRUCTOR = ROOT / "infrastructure" / "scripts" / "instructor"
RESOLVER_PATH = INSTRUCTOR / "resolve-image-digests.py"
SPEC = importlib.util.spec_from_file_location("live_digest_resolver", RESOLVER_PATH)
assert SPEC is not None and SPEC.loader is not None
resolver = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = resolver
SPEC.loader.exec_module(resolver)


def read(name: str) -> str:
    return (INSTRUCTOR / name).read_text(encoding="utf-8")


class DigestResolverTest(unittest.TestCase):
    def test_bearer_challenge_is_parsed_without_retaining_realm_as_query(self) -> None:
        realm, parameters = resolver._parse_bearer_challenge(
            'Bearer realm="https://ghcr.io/token",'
            'service="ghcr.io",'
            'scope="repository:example/image:pull"'
        )
        self.assertEqual(realm, "https://ghcr.io/token")
        self.assertEqual(parameters["service"], "ghcr.io")
        self.assertEqual(parameters["scope"], "repository:example/image:pull")
        self.assertNotIn("realm", parameters)

    def test_linux_amd64_selection_is_exact_and_rejects_ambiguity(self) -> None:
        digest = "sha256:" + "a" * 64
        document = {
            "manifests": [
                {
                    "digest": "sha256:" + "b" * 64,
                    "platform": {"os": "linux", "architecture": "arm64"},
                },
                {
                    "digest": digest,
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
            ]
        }
        self.assertEqual(resolver._select_linux_amd64(document), digest)
        document["manifests"].append(
            {
                "digest": "sha256:" + "c" * 64,
                "platform": {"os": "linux", "architecture": "amd64"},
            }
        )
        with self.assertRaises(resolver.ResolutionError):
            resolver._select_linux_amd64(document)

    def test_ghcr_anonymous_challenge_resolves_and_verifies_body_digest(self) -> None:
        body = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
            },
            separators=(",", ":"),
        ).encode()
        digest = "sha256:" + hashlib.sha256(body).hexdigest()

        class Response:
            def __init__(self, payload: bytes, headers: Message | None = None):
                self.payload = payload
                self.headers = headers or Message()

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self) -> bytes:
                return self.payload

        class FakeGhcrClient(resolver.RegistryClient):
            def __init__(self):
                super().__init__("ghcr.io", 5)
                self.urls: list[str] = []

            def _open(self, request):
                self.urls.append(request.full_url)
                if request.full_url.startswith("https://ghcr.io/token?"):
                    return Response(b'{"token":"ephemeral-test-token"}')
                if request.get_header("Authorization") is None:
                    headers = Message()
                    headers["WWW-Authenticate"] = (
                        'Bearer realm="https://ghcr.io/token",service="ghcr.io",'
                        'scope="repository:gasbugs/owasp-llm-vuln-rag:pull"'
                    )
                    raise urllib.error.HTTPError(
                        request.full_url, 401, "unauthorized", headers, None
                    )
                headers = Message()
                headers["Content-Type"] = "application/vnd.oci.image.manifest.v1+json"
                headers["Docker-Content-Digest"] = digest
                return Response(body, headers)

        client = FakeGhcrClient()
        response = client.get_manifest(
            "gasbugs/owasp-llm-vuln-rag", "sha-" + "a" * 40
        )
        self.assertEqual(response.digest, digest)
        self.assertEqual(client.urls[0].split("/v2/", 1)[0], "https://ghcr.io")
        self.assertTrue(any(url.startswith("https://ghcr.io/token?") for url in client.urls))

    def test_resolved_document_has_tag_and_platform_digests_for_five_images(self) -> None:
        tag_digest = "sha256:" + "1" * 64
        child_digest = "sha256:" + "2" * 64

        class FakeClient:
            def get_manifest(self, repository: str, reference: str):
                if reference.startswith("sha-"):
                    return resolver.ManifestResponse(
                        tag_digest,
                        "application/vnd.oci.image.index.v1+json",
                        b"{}",
                        {
                            "manifests": [
                                {
                                    "digest": child_digest,
                                    "platform": {
                                        "os": "linux",
                                        "architecture": "amd64",
                                    },
                                }
                            ]
                        },
                    )
                if reference != child_digest:
                    raise AssertionError(f"unexpected child reference: {reference}")
                return resolver.ManifestResponse(
                    child_digest,
                    "application/vnd.oci.image.manifest.v1+json",
                    b"{}",
                    {},
                )

        result = resolver.resolve_images(
            "ghcr.io", "gasbugs", "sha-" + "a" * 40, FakeClient()
        )
        self.assertEqual(len(result["images"]), 5)
        self.assertTrue(
            all(item["tag_digest"] == tag_digest for item in result["images"])
        )
        self.assertTrue(
            all(
                item["linux_amd64_digest"] == child_digest
                for item in result["images"]
            )
        )

    def test_moving_or_malformed_tags_fail_before_registry_access(self) -> None:
        class NeverCalled:
            def get_manifest(self, repository: str, reference: str):
                raise AssertionError("registry must not be queried")

        for tag in ("latest", "sha-main", "sha-" + "A" * 40):
            with self.subTest(tag=tag), self.assertRaises(resolver.ResolutionError):
                resolver.resolve_images("ghcr.io", "gasbugs", tag, NeverCalled())
        with self.assertRaises(resolver.ResolutionError):
            resolver.resolve_images(
                "docker.io", "gasbugs", "sha-" + "a" * 40, NeverCalled()
            )


class LiveControllerContractTest(unittest.TestCase):
    def test_shell_scripts_parse_and_help_has_no_side_effect(self) -> None:
        for name in (
            "run-commit-live-validation.sh",
            "run-remote-validation.sh",
        ):
            result = subprocess.run(
                ["bash", "-n", str(INSTRUCTOR / name)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

        help_result = subprocess.run(
            ["bash", str(INSTRUCTOR / "run-commit-live-validation.sh"), "--help"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("There is no preserve-resources option", help_result.stdout)

    def test_controller_fixes_canonical_ghcr_source_and_derives_sha_tag(self) -> None:
        source = read("run-commit-live-validation.sh")
        self.assertIn(': "${IMAGE_REGISTRY:=ghcr.io}"', source)
        self.assertIn(': "${IMAGE_NAMESPACE:=gasbugs}"', source)
        self.assertIn('canonical image source must be ghcr.io/gasbugs', source)
        self.assertIn('IMAGE_TAG="sha-$SETUP_COMMIT"', source)
        self.assertNotIn('"-var=lab_image_registry=', source)
        self.assertIn('"-var=lab_image_namespace=$IMAGE_NAMESPACE"', source)
        self.assertIn('"-var=lab_image_tag=$IMAGE_TAG"', source)

    def test_cost_and_cleanup_contracts_are_fail_closed(self) -> None:
        source = read("run-commit-live-validation.sh")
        self.assertIn("EMERGENCY_STOP_MINUTES:=120", source)
        self.assertIn('"-var=enable_auto_stop=true"', source)
        self.assertIn('"-var=auto_stop_schedule_mode=custom"', source)
        self.assertIn("trap cleanup EXIT", source)
        self.assertIn('terraform -chdir="$TF_DIR" destroy', source)
        self.assertIn("direct_residual_audit", source)
        self.assertIn("terminate_instances_direct", source)
        self.assertLess(
            source.index("terminate_instances_direct"),
            source.index('terraform -chdir="$TF_DIR" destroy'),
        )
        self.assertIn("Existing Terraform state aborts", source)
        self.assertNotIn("PRESERVE", source)
        self.assertNotIn("SKIP_DESTROY", source)

    def test_absent_initial_terraform_state_is_treated_as_empty(self) -> None:
        source = read("run-commit-live-validation.sh")
        state_guard = source.index('if [ -f "$TF_DIR/terraform.tfstate" ]; then')
        state_list = source.index(
            'existing_state=$(terraform -chdir="$TF_DIR" state list)', state_guard
        )
        state_abort = source.index(
            'if [ -n "$existing_state" ]; then', state_list
        )
        self.assertLess(state_guard, state_list)
        self.assertLess(state_list, state_abort)

    def test_remote_runner_uses_strict_exit_codes_and_archives_every_failure(self) -> None:
        source = read("run-remote-validation.sh")
        self.assertIn("trap finalize EXIT", source)
        self.assertIn("STRICT_ACCEPTANCE=true TRIALS=5", source)
        self.assertIn("run-full-cycle.sh", source)
        self.assertIn("llm09-candidates.jsonl", source)
        self.assertIn("run-isolated-slopsquat.sh", source)
        self.assertIn("solutions/validate-live.sh", source)
        self.assertIn("BASE_IMAGE_OVERRIDE=\"$BASE_GPU_REF\"", source)
        self.assertIn("org.opencontainers.image.revision", source)
        self.assertIn("BROWSER_READY run_id=$RUN_ID", source)
        self.assertIn('cp -a "$E2E_DIR" "$RUN_ROOT/full-cycle-evidence"', source)
        self.assertIn('tar -C "$(dirname "$RUN_ROOT")"', source)
        self.assertIn('sha256sum "$(basename "$ARCHIVE")"', source)

        digest_failure = source.index("FAIL: immutable runtime digest gate")
        full_cycle = source.index('STRICT_ACCEPTANCE=true TRIALS=5')
        self.assertLess(digest_failure, full_cycle)
        self.assertIn("exit 1", source[digest_failure:full_cycle])

    def test_controller_downloads_before_mandatory_destroy(self) -> None:
        source = read("run-commit-live-validation.sh")
        cleanup = source.split("cleanup() {", 1)[1]
        self.assertLess(
            cleanup.index("download_remote_evidence"),
            cleanup.index("Terraform destroy started"),
        )
        self.assertIn("SHA-256 verified", source)
        self.assertIn("fallback-instance.log", source)

    def test_setup_course_terraform_and_browser_sources_are_immutable(self) -> None:
        source = read("run-commit-live-validation.sh")
        self.assertIn(': "${COURSE_COMMIT:?COURSE_COMMIT is required', source)
        self.assertIn('status --porcelain=v1 --untracked-files=all', source)
        self.assertIn('merge-base --is-ancestor "$COURSE_COMMIT" origin/main', source)
        self.assertIn('archive --format=tar "$COURSE_COMMIT" capstone', source)
        self.assertIn('archive --format=tar "$SETUP_COMMIT"', source)
        self.assertIn('TF_DIR="$PINNED_REPO/infrastructure/terraform"', source)
        self.assertNotIn(': "${TF_DIR:=', source)
        self.assertIn('tests/browser/run_day3_ui.py', source)
        self.assertIn('run-bounded-command.py', source)

    def test_browser_handoff_is_background_bounded_atomic_and_fail_closed(self) -> None:
        source = read("run-commit-live-validation.sh")
        background = source.index('>"$LOCAL_RUN_DIR/remote-run.log" 2>&1 &')
        ready = source.index('BROWSER_READY run_id=$RUN_ID', background)
        forward = source.index('start_port_forward 8011 18011', ready)
        browser = source.index('run_day3_ui.py', forward)
        upload_partial = source.index('browser-controller-result.json.partial', browser)
        atomic_move = source.index('browser-controller-result.json"', upload_partial)
        remote_wait = source.index('wait "$REMOTE_PROCESS_PID"', atomic_move)
        download = source.index('download_remote_evidence', remote_wait)
        self.assertLess(background, ready)
        self.assertLess(ready, forward)
        self.assertLess(forward, browser)
        self.assertLess(browser, upload_partial)
        self.assertLess(upload_partial, atomic_move)
        self.assertLess(atomic_move, remote_wait)
        self.assertLess(remote_wait, download)
        self.assertIn('controller-synthetic-failure.txt', source)
        self.assertIn('PORT_FORWARD_PIDS', source)
        self.assertIn('sock.bind(("127.0.0.1", port))', source)

        early_exit = source.split(
            'if ! kill -0 "$REMOTE_PROCESS_PID" >/dev/null 2>&1; then', 1
        )[1].split("  fi\n  sleep 5", 1)[0]
        self.assertIn("REMOTE_REPORTED_RC=$?", early_exit)
        self.assertIn("REMOTE_RC=1", early_exit)
        self.assertIn("BROWSER_RC=1", early_exit)
        self.assertIn("exit 1", early_exit)
        self.assertNotIn('exit "$REMOTE_RC"', early_exit)
        self.assertIn("remote_reported_rc:$remote_reported_rc", source)

    def test_empty_port_forward_array_is_safe_on_macos_bash(self) -> None:
        source = read("run-commit-live-validation.sh")
        cleanup = source.split("stop_port_forwards() {", 1)[1].split("\n}", 1)[0]
        guard = cleanup.index('if [ "${#PORT_FORWARD_PIDS[@]}" -gt 0 ]; then')
        first_expansion = cleanup.index('for pid in "${PORT_FORWARD_PIDS[@]}"', guard)
        self.assertLess(guard, first_expansion)

        result = subprocess.run(
            [
                "/bin/bash",
                "-uc",
                'pids=(); if [ "${#pids[@]}" -gt 0 ]; then '
                'for pid in "${pids[@]}"; do :; done; fi',
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        termination = source.split("terminate_instances_direct() {", 1)[1].split(
            "\n}", 1
        )[0]
        instance_guard = termination.index(
            'if [ "${#instance_ids[@]}" -gt 0 ]; then'
        )
        instance_expansion = termination.index(
            'for existing in "${instance_ids[@]}"', instance_guard
        )
        self.assertLess(instance_guard, instance_expansion)

    def test_controller_result_binds_course_provenance_fields(self) -> None:
        source = read("run-commit-live-validation.sh")
        cleanup = source.split("cleanup() {", 1)[1]
        self.assertIn('--arg course_commit "$COURSE_COMMIT"', cleanup)
        self.assertIn('--arg course_tree_hash "$COURSE_TREE_HASH"', cleanup)
        self.assertIn('course_commit:$course_commit', cleanup)
        self.assertIn('course_tree_hash:$course_tree_hash', cleanup)

    def test_bounded_runner_times_out_without_leaving_the_command_running(self) -> None:
        runner = INSTRUCTOR / "run-bounded-command.py"
        runner_source = runner.read_text(encoding="utf-8")
        self.assertIn("start_new_session=True", runner_source)
        self.assertIn("os.killpg", runner_source)
        self.assertIn("signal.SIGHUP", runner_source)
        started = time.monotonic()
        result = subprocess.run(
            [
                sys.executable,
                str(runner),
                "1",
                sys.executable,
                "-c",
                "import time; time.sleep(30)",
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=8,
        )
        self.assertEqual(124, result.returncode, result.stderr)
        self.assertLess(time.monotonic() - started, 6)


if __name__ == "__main__":
    unittest.main()
