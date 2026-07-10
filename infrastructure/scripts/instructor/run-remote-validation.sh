#!/bin/bash
# Execute the commit-pinned runtime, LLM09 isolation, and Day 5 reference checks
# on a single instructor EC2 host.  The local controller retrieves the archive.
set -uo pipefail

: "${SETUP_COMMIT:?SETUP_COMMIT is required}"
: "${IMAGE_REGISTRY:?IMAGE_REGISTRY is required}"
: "${IMAGE_NAMESPACE:?IMAGE_NAMESPACE is required}"
: "${IMAGE_TAG:?IMAGE_TAG is required}"
: "${EXPECTED_DIGESTS_FILE:?EXPECTED_DIGESTS_FILE is required}"
: "${RUN_ID:?RUN_ID is required}"
: "${BROWSER_HANDOFF_DEADLINE_EPOCH:?BROWSER_HANDOFF_DEADLINE_EPOCH is required}"
: "${COURSE_CAPSTONE_DIR:=/home/ubuntu/work/my-capstone}"
: "${HOME:=/home/ubuntu}"

export HOME

if [[ ! "$SETUP_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ERROR: SETUP_COMMIT must be a 40-character lowercase Git commit" >&2
  exit 2
fi
if [ "$IMAGE_REGISTRY" != "ghcr.io" ] || [ "$IMAGE_NAMESPACE" != "gasbugs" ]; then
  echo "ERROR: canonical image source must be ghcr.io/gasbugs" >&2
  exit 2
fi
if [ "$IMAGE_TAG" != "sha-$SETUP_COMMIT" ]; then
  echo "ERROR: IMAGE_TAG must equal sha-SETUP_COMMIT" >&2
  exit 2
fi
if [[ ! "$RUN_ID" =~ ^[a-zA-Z0-9._-]{3,100}$ ]]; then
  echo "ERROR: RUN_ID contains unsafe characters" >&2
  exit 2
fi
if [[ ! "$BROWSER_HANDOFF_DEADLINE_EPOCH" =~ ^[0-9]{10}$ ]] \
  || [ "$BROWSER_HANDOFF_DEADLINE_EPOCH" -le "$(date +%s)" ]; then
  echo "ERROR: browser hand-off deadline must be a future epoch" >&2
  exit 2
fi

for command in git jq curl python3 tar sha256sum podman; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "ERROR: required remote command not found: $command" >&2
    exit 2
  }
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
if [ "$(git -C "$REPO_ROOT" rev-parse HEAD)" != "$SETUP_COMMIT" ]; then
  echo "ERROR: remote setup checkout does not match SETUP_COMMIT" >&2
  exit 2
fi

RUN_ROOT="$HOME/work/live-validation/$RUN_ID"
ARCHIVE_ROOT="$HOME/work/live-validation-archives"
ARCHIVE="$ARCHIVE_ROOT/$RUN_ID.tgz"
ARCHIVE_SHA="$ARCHIVE.sha256"
mkdir -p "$RUN_ROOT" "$ARCHIVE_ROOT"
chmod 0700 "$RUN_ROOT" "$ARCHIVE_ROOT"
cp "$EXPECTED_DIGESTS_FILE" "$RUN_ROOT/expected-image-digests.json"

DIGEST_RC=99
FULL_CYCLE_RC=99
SLOPSQUAT_RC=99
DAY5_RC=99
BROWSER_RC=99
E2E_DIR=""
SLOPSQUAT_PACKAGE=""
BASE_GPU_REF=""
FINALIZED=0

write_summary() {
  jq -n \
    --arg run_id "$RUN_ID" \
    --arg setup_commit "$SETUP_COMMIT" \
    --arg image_registry "$IMAGE_REGISTRY" \
    --arg image_namespace "$IMAGE_NAMESPACE" \
    --arg image_tag "$IMAGE_TAG" \
    --arg e2e_dir "$E2E_DIR" \
    --arg slopsquat_package "$SLOPSQUAT_PACKAGE" \
    --arg base_gpu_ref "$BASE_GPU_REF" \
    --arg validated_at "$(date -Iseconds)" \
    --argjson digest_rc "$DIGEST_RC" \
    --argjson full_cycle_rc "$FULL_CYCLE_RC" \
    --argjson slopsquat_rc "$SLOPSQUAT_RC" \
    --argjson day5_rc "$DAY5_RC" \
    --argjson browser_rc "$BROWSER_RC" \
    '{schema:"owasp-llm-remote-validation/v1", run_id:$run_id,
      setup_commit:$setup_commit, image_registry:$image_registry,
      image_namespace:$image_namespace,
      image_tag:$image_tag, validated_at:$validated_at,
      stages:{runtime_digest:$digest_rc, strict_full_cycle:$full_cycle_rc,
        isolated_slopsquat:$slopsquat_rc, day5_live:$day5_rc,
        day3_browser_ui:$browser_rc},
      evidence:{full_cycle_dir:$e2e_dir, slopsquat_package:$slopsquat_package,
        day5_base_image:$base_gpu_ref}}' \
    > "$RUN_ROOT/summary.json"
}

finalize() {
  local original_rc=$?
  [ "$FINALIZED" -eq 0 ] || return
  FINALIZED=1
  trap - EXIT
  set +e

  local summary_rc=0
  write_summary || summary_rc=1
  sudo tail -n 500 /var/log/user-data.log >"$RUN_ROOT/user-data-tail.log" 2>&1 || true
  sudo tail -n 1000 /var/log/owasp-llm-lab-install.log \
    >"$RUN_ROOT/install-tail.log" 2>&1 || true
  sudo -u ubuntu podman ps -a --format json >"$RUN_ROOT/podman-ps.json" 2>&1 || true
  git -C "$REPO_ROOT" status --porcelain=v1 >"$RUN_ROOT/setup-git-status.txt" 2>&1 || true

  (
    cd "$RUN_ROOT" || exit 1
    find . -type f ! -name file-sha256.txt -print0 \
      | LC_ALL=C sort -z \
      | xargs -0 sha256sum > file-sha256.txt
  )
  local manifest_rc=$?

  local temporary_archive="$ARCHIVE.partial"
  rm -f "$temporary_archive" "$ARCHIVE" "$ARCHIVE_SHA"
  tar -C "$(dirname "$RUN_ROOT")" -czf "$temporary_archive" "$(basename "$RUN_ROOT")"
  local tar_rc=$?
  if [ "$tar_rc" -eq 0 ]; then
    mv "$temporary_archive" "$ARCHIVE"
    (
      cd "$ARCHIVE_ROOT" || exit 1
      sha256sum "$(basename "$ARCHIVE")" >"$(basename "$ARCHIVE_SHA")"
    )
    tar_rc=$?
  fi
  chmod 0600 "$ARCHIVE" "$ARCHIVE_SHA" 2>/dev/null || true

  if [ "$summary_rc" -ne 0 ] || [ "$manifest_rc" -ne 0 ] || [ "$tar_rc" -ne 0 ]; then
    echo "ERROR: remote evidence archive could not be finalized" >&2
    original_rc=1
  else
    echo "REMOTE_ARCHIVE=$ARCHIVE"
    echo "REMOTE_SHA256=$ARCHIVE_SHA"
  fi
  exit "$original_rc"
}
trap finalize EXIT

actual_namespace=$(sed -n 's/^IMAGE_NAMESPACE=//p' /etc/lab/env 2>/dev/null | tail -1)
actual_tag=$(sed -n 's/^IMAGE_TAG=//p' /etc/lab/env 2>/dev/null | tail -1)
if [ "$actual_namespace" != "$IMAGE_NAMESPACE" ] \
  || [ "$actual_tag" != "$IMAGE_TAG" ]; then
  echo "ERROR: /etc/lab/env does not match the requested immutable image set" >&2
  DIGEST_RC=1
else
  echo "PASS: /etc/lab/env namespace and tag match"
fi

if ! jq -e \
  --arg registry "$IMAGE_REGISTRY" --arg namespace "$IMAGE_NAMESPACE" --arg tag "$IMAGE_TAG" '
    .schema == "owasp-llm-image-digests/v1"
    and .registry == $registry and .namespace == $namespace and .tag == $tag
    and (.images | length == 5)
    and ([.images[].name] | sort
      == ["base-gpu","dvla","llmgoat","vuln-agent","vuln-rag"])
    and ([.images[]
      | .reference == ($registry + "/" + $namespace + "/owasp-llm-" + .name + ":" + $tag)]
      | all)
    and ([.images[].tag_digest
      | test("^sha256:[0-9a-f]{64}$")] | all)
    and ([.images[].linux_amd64_digest
      | test("^sha256:[0-9a-f]{64}$")] | all)
  ' "$EXPECTED_DIGESTS_FILE" >/dev/null; then
  echo "ERROR: expected image digest manifest is invalid" >&2
  DIGEST_RC=1
fi

runtime_jsonl="$RUN_ROOT/runtime-images.jsonl"
: >"$runtime_jsonl"
if [ "$DIGEST_RC" -ne 1 ]; then
  base_gpu_digest=$(jq -er '.images[] | select(.name == "base-gpu")
    | .linux_amd64_digest' "$EXPECTED_DIGESTS_FILE")
  BASE_GPU_REF="$IMAGE_REGISTRY/$IMAGE_NAMESPACE/owasp-llm-base-gpu@$base_gpu_digest"
  DIGEST_RC=0
  while IFS=$'\t' read -r name reference expected_tag_digest expected_platform_digest; do
    inspect_file="$RUN_ROOT/podman-image-$name.json"
    if ! sudo -u ubuntu podman image inspect "$reference" >"$inspect_file"; then
      echo "ERROR: required image is absent from Podman storage: $reference" >&2
      DIGEST_RC=1
      continue
    fi
    if ! jq -e \
      --arg tag_digest "$expected_tag_digest" \
      --arg platform_digest "$expected_platform_digest" \
      --arg setup_commit "$SETUP_COMMIT" '
      .[0] as $image
      | ($image.Architecture == "amd64")
      and (($image.Os // "linux") == "linux")
      and ($image.Labels["org.opencontainers.image.revision"] == $setup_commit)
      and ([ $image.Digest // empty,
             ($image.RepoDigests[]? | split("@")[-1]) ]
           | any(. == $tag_digest or . == $platform_digest))
    ' "$inspect_file" >/dev/null; then
      echo "ERROR: pulled digest mismatch for $reference" >&2
      DIGEST_RC=1
      continue
    fi
    jq -c --arg name "$name" --arg reference "$reference" \
      --arg expected_tag "$expected_tag_digest" \
      --arg expected_platform "$expected_platform_digest" \
      --arg setup_commit "$SETUP_COMMIT" '
      .[0] | {name:$name, reference:$reference,
        expected_tag_digest:$expected_tag,
        expected_linux_amd64_digest:$expected_platform, image_id:.Id,
        expected_revision:$setup_commit,
        actual_revision:.Labels["org.opencontainers.image.revision"],
        stored_digest:(.Digest // null), repo_digests:(.RepoDigests // [])}
    ' "$inspect_file" >>"$runtime_jsonl"
  done < <(jq -r '.images[] | [.name,.reference,.tag_digest,.linux_amd64_digest] | @tsv' \
    "$EXPECTED_DIGESTS_FILE")
fi
jq -s '.' "$runtime_jsonl" >"$RUN_ROOT/runtime-images.json" || DIGEST_RC=1

if [ "$DIGEST_RC" -eq 0 ]; then
  echo "PASS: all five exact linux/amd64 image digests are present"
else
  echo "FAIL: immutable runtime digest gate" >&2
  FULL_CYCLE_RC=1
  SLOPSQUAT_RC=1
  DAY5_RC=1
  BROWSER_RC=1
  exit 1
fi

before_dirs="$RUN_ROOT/e2e-before.txt"
after_dirs="$RUN_ROOT/e2e-after.txt"
find "$HOME/work/e2e-evidence" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null \
  | LC_ALL=C sort >"$before_dirs" || true

set +e
STRICT_ACCEPTANCE=true TRIALS=5 \
  bash "$REPO_ROOT/tests/e2e/run-full-cycle.sh" \
  2>&1 | tee "$RUN_ROOT/strict-full-cycle.log"
full_cycle_pipeline=("${PIPESTATUS[@]}")
FULL_CYCLE_RC=${full_cycle_pipeline[0]}
if [ "${full_cycle_pipeline[1]}" -ne 0 ]; then
  echo "ERROR: strict full-cycle log could not be preserved" >&2
  FULL_CYCLE_RC=1
fi
set -u

find "$HOME/work/e2e-evidence" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null \
  | LC_ALL=C sort >"$after_dirs" || true
mapfile -t new_e2e_dirs < <(comm -13 "$before_dirs" "$after_dirs")
if [ "${#new_e2e_dirs[@]}" -eq 1 ]; then
  E2E_DIR="${new_e2e_dirs[0]}"
elif [ "${#new_e2e_dirs[@]}" -gt 1 ]; then
  E2E_DIR="${new_e2e_dirs[${#new_e2e_dirs[@]}-1]}"
else
  E2E_DIR=$(sed -n 's/.*완료\. 결과: //p' "$RUN_ROOT/strict-full-cycle.log" | tail -1)
fi
if [ -n "$E2E_DIR" ] && [ -d "$E2E_DIR" ]; then
  if ! cp -a "$E2E_DIR" "$RUN_ROOT/full-cycle-evidence"; then
    echo "ERROR: full-cycle raw evidence copy failed" >&2
    FULL_CYCLE_RC=1
  fi
else
  echo "ERROR: full-cycle evidence directory was not found" >&2
  FULL_CYCLE_RC=1
fi

candidate_file="$E2E_DIR/llm09/llm09-candidates.jsonl"
if [ -f "$candidate_file" ]; then
  SLOPSQUAT_PACKAGE=$(python3 - "$candidate_file" <<'PY'
import json
import re
import sys

for line in open(sys.argv[1], encoding="utf-8"):
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue
    if item.get("candidate_type") != "package":
        continue
    if item.get("classification") != "hallucinated_package":
        continue
    if item.get("http_status") not in (404, 410):
        continue
    candidate = re.sub(r"[-_.]+", "-", str(item.get("candidate", "")).lower())
    if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", candidate):
        print(candidate)
        break
PY
  )
fi

if [ -z "$SLOPSQUAT_PACKAGE" ]; then
  echo "FAIL: full-cycle produced no current LLM09 NOT_FOUND package candidate" >&2
  SLOPSQUAT_RC=1
else
  echo "LLM09 isolated candidate=$SLOPSQUAT_PACKAGE"
  set +e
  SLOPSQUAT_PACKAGE="$SLOPSQUAT_PACKAGE" \
    RESULTS_DIR="$RUN_ROOT/llm09-isolated" \
    bash "$REPO_ROOT/tests/e2e/llm09/run-isolated-slopsquat.sh" \
    2>&1 | tee "$RUN_ROOT/llm09-isolated.log"
  slopsquat_pipeline=("${PIPESTATUS[@]}")
  SLOPSQUAT_RC=${slopsquat_pipeline[0]}
  if [ "${slopsquat_pipeline[1]}" -ne 0 ]; then
    echo "ERROR: isolated LLM09 log could not be preserved" >&2
    SLOPSQUAT_RC=1
  fi
  set -u
fi

day5_harness="$COURSE_CAPSTONE_DIR/solutions/validate-live.sh"
if [ ! -f "$day5_harness" ]; then
  echo "FAIL: Day 5 live-validation harness not found: $day5_harness" >&2
  DAY5_RC=1
else
  set +e
  EVIDENCE_DIR="$RUN_ROOT/day5-live-evidence" \
    RUN_REAL_MODEL_NORMAL=1 \
    RUN_LLAMA_GUARD_PROBE=1 \
    UPSTREAM_OLLAMA_URL=http://127.0.0.1:11434 \
    BASE_IMAGE_OVERRIDE="$BASE_GPU_REF" \
    bash "$day5_harness" 2>&1 | tee "$RUN_ROOT/day5-live.log"
  day5_pipeline=("${PIPESTATUS[@]}")
  DAY5_RC=${day5_pipeline[0]}
  if [ "${day5_pipeline[1]}" -ne 0 ]; then
    echo "ERROR: Day 5 live-validation log could not be preserved" >&2
    DAY5_RC=1
  fi
  day5_result="$RUN_ROOT/day5-live-evidence/result.json"
  starter_inspect="$RUN_ROOT/day5-live-evidence/build/starter-image-inspect.json"
  reference_inspect="$RUN_ROOT/day5-live-evidence/build/reference-image-inspect.json"
  if [ ! -f "$day5_result" ] \
    || [ ! -f "$starter_inspect" ] || [ ! -f "$reference_inspect" ] \
    || ! jq -e \
      --arg expected_base "$BASE_GPU_REF" \
      --slurpfile starter "$starter_inspect" \
      --slurpfile reference "$reference_inspect" '
        .builds.base_image_override == $expected_base
        and ($starter[0][0].Labels["org.opencontainers.image.source-fingerprint"]
          == .builds.starter.source_fingerprint)
        and ($reference[0][0].Labels["org.opencontainers.image.source-fingerprint"]
          == .builds.reference.source_fingerprint)
      ' "$day5_result" >/dev/null \
    || ! grep -Fq "$BASE_GPU_REF" \
      "$RUN_ROOT/day5-live-evidence/build/starter-build.log" \
    || ! grep -Fq "$BASE_GPU_REF" \
      "$RUN_ROOT/day5-live-evidence/build/reference-build.log"; then
    echo "ERROR: Day 5 build did not prove the commit-pinned base image provenance" >&2
    DAY5_RC=1
  fi
  set -u
fi

write_summary

# The browser must run on the instructor machine through SSM port forwards.
# Keep the instance alive only for this bounded hand-off, then include the
# returned local evidence in the same archive before the controller destroys EC2.
browser_ready="$RUN_ROOT/browser-controller-ready"
browser_control="$RUN_ROOT/browser-controller-result.json"
browser_ready_partial="$browser_ready.partial"
jq -n \
  --argjson deadline "$BROWSER_HANDOFF_DEADLINE_EPOCH" \
  --arg ready_at "$(date -Iseconds)" \
  '{schema:"owasp-llm-browser-ready/v1",ready_at:$ready_at,
    handoff_deadline_epoch:$deadline}' >"$browser_ready_partial"
mv "$browser_ready_partial" "$browser_ready"
echo "BROWSER_READY run_id=$RUN_ID deadline=$BROWSER_HANDOFF_DEADLINE_EPOCH"
browser_deadline="$BROWSER_HANDOFF_DEADLINE_EPOCH"
while [ ! -f "$browser_control" ] && [ "$(date +%s)" -lt "$browser_deadline" ]; do
  sleep 2
done
if [ ! -f "$browser_control" ]; then
  echo "FAIL: controller did not return Day 3 browser evidence before the shared deadline" >&2
  BROWSER_RC=1
elif ! python3 - "$RUN_ROOT/browser-evidence" "$browser_control" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

evidence = pathlib.Path(sys.argv[1]).resolve()
control_path = pathlib.Path(sys.argv[2]).resolve()
control = json.loads(control_path.read_text(encoding="utf-8"))
browser_rc = control.get("browser_rc")
if not isinstance(browser_rc, int) or not 0 <= browser_rc <= 255:
    raise SystemExit("invalid browser_rc")
if control.get("forward_cleanup") != "PASS":
    raise SystemExit("SSM port-forward cleanup was not proven")

result_path = evidence / "result.json"
manifest_path = evidence / "sha256sums.json"
if not result_path.is_file() or not manifest_path.is_file():
    raise SystemExit("browser result or hash manifest is missing")

def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

if sha256(result_path) != control.get("result_sha256"):
    raise SystemExit("browser result hash mismatch")
if sha256(manifest_path) != control.get("manifest_sha256"):
    raise SystemExit("browser manifest hash mismatch")

manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
if not isinstance(manifest, dict) or not manifest:
    raise SystemExit("browser hash manifest is empty")
for relative, expected in manifest.items():
    if not isinstance(relative, str) or not isinstance(expected, str):
        raise SystemExit("browser hash manifest has invalid types")
    candidate = (evidence / relative).resolve()
    try:
        candidate.relative_to(evidence)
    except ValueError as exc:
        raise SystemExit("browser hash manifest escapes evidence root") from exc
    if not candidate.is_file() or sha256(candidate) != expected:
        raise SystemExit(f"browser evidence hash mismatch: {relative}")

result = json.loads(result_path.read_text(encoding="utf-8"))
if browser_rc == 0:
    if result.get("status") != "PASS":
        raise SystemExit("zero browser_rc disagrees with result status")
    if result.get("cleanup", {}).get("status") != "PASS":
        raise SystemExit("browser/receiver cleanup was not proven")
else:
    if result.get("status") == "PASS":
        raise SystemExit("nonzero browser_rc disagrees with result status")
print(browser_rc)
PY
then
  echo "FAIL: returned Day 3 browser evidence failed integrity/cleanup checks" >&2
  BROWSER_RC=1
else
  BROWSER_RC=$(jq -er '.browser_rc' "$browser_control")
fi

write_summary

overall_rc=0
for stage_rc in \
  "$DIGEST_RC" "$FULL_CYCLE_RC" "$SLOPSQUAT_RC" "$DAY5_RC" "$BROWSER_RC"; do
  if [ "$stage_rc" -ne 0 ]; then
    overall_rc=1
  fi
done

if [ "$overall_rc" -eq 0 ]; then
  echo "PASS: remote validation stages completed"
else
  echo "FAIL: one or more remote validation stages failed; evidence will still be archived" >&2
fi
exit "$overall_rc"
