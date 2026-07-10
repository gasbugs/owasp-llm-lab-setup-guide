#!/bin/bash
# Cost-bounded controller for one immutable instructor EC2 validation run.
#
# This script intentionally has no "keep instance" mode.  Once terraform apply
# starts, the EXIT trap retrieves available evidence and destroys the stack.
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  SETUP_COMMIT=<40-char-main-commit> \
  COURSE_COMMIT=<40-char-main-commit> \
  COURSE_REPO=/absolute/path/to/owasp-top-10-for-llm \
  ALERT_EMAIL=instructor@example.com \
  AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT=validator \
    bash infrastructure/scripts/instructor/run-commit-live-validation.sh

Required inputs:
  SETUP_COMMIT      Published setup-repository main commit.
  COURSE_COMMIT     Published, clean course-repository main commit.
  COURSE_REPO      Local course checkout whose capstone harness is uploaded.
  ALERT_EMAIL      SNS/Budget alert endpoint required by the Terraform stack.

Canonical public image source:
  IMAGE_REGISTRY=ghcr.io
  IMAGE_NAMESPACE=gasbugs

Safety controls:
  * IMAGE_TAG is derived as sha-$SETUP_COMMIT; latest is never accepted.
  * Existing Terraform state aborts the run before apply.
  * EC2 ingress remains 127.0.0.1/32 and SSM is used for transport.
  * A custom emergency auto-stop is applied with the EC2 stack.
  * Every wait and remote command has a deadline.
  * The EXIT trap downloads evidence when possible, always runs destroy, and
    performs direct AWS residual checks. There is no preserve-resources option.

Optional controls:
  EMERGENCY_STOP_MINUTES=120   (allowed: 30..180)
  LOCAL_EVIDENCE_ROOT=$HOME/owasp-llm-live-evidence
  BROWSER_PYTHON=python3
  PLAYWRIGHT_BROWSER_CHANNEL=chrome
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi
if [ "$#" -ne 0 ]; then
  usage >&2
  exit 2
fi

: "${SETUP_COMMIT:?SETUP_COMMIT is required; see --help}"
: "${COURSE_COMMIT:?COURSE_COMMIT is required; see --help}"
: "${COURSE_REPO:?COURSE_REPO is required}"
: "${ALERT_EMAIL:?ALERT_EMAIL is required by the Terraform alert resources}"
: "${AWS_PROFILE:=owasp-llm}"
: "${AWS_REGION:=us-east-1}"
: "${STUDENT:=validator}"
: "${EMERGENCY_STOP_MINUTES:=120}"
: "${IMAGE_REGISTRY:=ghcr.io}"
: "${IMAGE_NAMESPACE:=gasbugs}"
SETUP_GIT_URL="https://github.com/gasbugs/owasp-llm-lab-setup-guide.git"
LLM09_FIXTURE_PACKAGE="owasp-llm-lab-nonexistent-candidate-20260711"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BOUND_RUNNER="$SCRIPT_DIR/run-bounded-command.py"
: "${LOCAL_EVIDENCE_ROOT:=$HOME/owasp-llm-live-evidence}"
: "${BROWSER_PYTHON:=python3}"
: "${PLAYWRIGHT_BROWSER_CHANNEL:=chrome}"

if [[ ! "$SETUP_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ERROR: SETUP_COMMIT must be a 40-character lowercase Git commit" >&2
  exit 2
fi
if [[ ! "$COURSE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ERROR: COURSE_COMMIT must be a 40-character lowercase Git commit" >&2
  exit 2
fi
if [ "$IMAGE_REGISTRY" != "ghcr.io" ] || [ "$IMAGE_NAMESPACE" != "gasbugs" ]; then
  echo "ERROR: canonical image source must be ghcr.io/gasbugs" >&2
  exit 2
fi
if [[ ! "$AWS_PROFILE" =~ ^[A-Za-z0-9_.@-]+$ ]]; then
  echo "ERROR: AWS_PROFILE contains unsafe characters" >&2
  exit 2
fi
if [[ ! "$AWS_REGION" =~ ^[a-z]{2}-[a-z]+-[0-9]+$ ]]; then
  echo "ERROR: AWS_REGION is invalid" >&2
  exit 2
fi
if [[ ! "$STUDENT" =~ ^[a-z0-9-]{2,30}$ ]]; then
  echo "ERROR: STUDENT must use lowercase letters, digits, or hyphens" >&2
  exit 2
fi
if [[ ! "$EMERGENCY_STOP_MINUTES" =~ ^[0-9]+$ ]] \
  || [ "$EMERGENCY_STOP_MINUTES" -lt 30 ] \
  || [ "$EMERGENCY_STOP_MINUTES" -gt 180 ]; then
  echo "ERROR: EMERGENCY_STOP_MINUTES must be an integer from 30 through 180" >&2
  exit 2
fi
if [[ ! "$ALERT_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
  echo "ERROR: ALERT_EMAIL is not a valid email address" >&2
  exit 2
fi

IMAGE_TAG="sha-$SETUP_COMMIT"
RUN_ID="$(date -u +%Y%m%d-%H%M%S)-${SETUP_COMMIT:0:12}"
COURSE_ID="live-$(date -u +%Y%m%d-%H%M)-$$"
LOCAL_RUN_DIR="$LOCAL_EVIDENCE_ROOT/$RUN_ID"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/owasp-llm-live.XXXXXX")"
DIGEST_MANIFEST="$LOCAL_RUN_DIR/expected-image-digests.json"
LOCAL_REMOTE_DIR="$LOCAL_RUN_DIR/remote"
CONTROL_LOG="$LOCAL_RUN_DIR/controller.log"
RESIDUAL_REPORT="$LOCAL_RUN_DIR/residual-audit.json"
COST_DEADLINE_EPOCH=0
SETUP_TREE_HASH=""
TERRAFORM_TREE_HASH=""
COURSE_TREE_HASH=""
PINNED_REPO="$WORK_DIR/pinned-setup"
PINNED_COURSE="$WORK_DIR/pinned-course"
TF_DIR="$PINNED_REPO/infrastructure/terraform"
REMOTE_REPO="/home/ubuntu/work/validation-setup-$RUN_ID"
REMOTE_DIGESTS="/home/ubuntu/work/expected-image-digests-$RUN_ID.json"
REMOTE_ARCHIVE_ROOT="/home/ubuntu/work/live-validation-archives"
REMOTE_ARCHIVE="$REMOTE_ARCHIVE_ROOT/$RUN_ID.tgz"
REMOTE_ARCHIVE_SHA="$REMOTE_ARCHIVE.sha256"
REMOTE_RUN_ROOT="/home/ubuntu/work/live-validation/$RUN_ID"

mkdir -p "$LOCAL_RUN_DIR" "$LOCAL_REMOTE_DIR"
chmod 0700 "$LOCAL_RUN_DIR" "$LOCAL_REMOTE_DIR"
: >"$CONTROL_LOG"
chmod 0600 "$CONTROL_LOG"
# Before the AWS-aware cleanup function is installed, only local temporary
# files exist. This early trap prevents preflight failures from leaking them.
trap 'rm -rf "$WORK_DIR"' EXIT

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$CONTROL_LOG"
}

run_bounded() {
  local timeout_seconds="$1"
  shift
  # The helper keeps stdin attached for SSH heredocs and owns the child process
  # group, so timeout/signal cleanup cannot orphan session-manager-plugin.
  python3 "$BOUND_RUNNER" "$timeout_seconds" "$@"
}

aws_cli() {
  run_bounded 45 aws \
    --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" \
    --no-cli-pager \
    --cli-connect-timeout 5 \
    --cli-read-timeout 30 \
    "$@"
}

seconds_remaining() {
  if [ "$COST_DEADLINE_EPOCH" -eq 0 ]; then
    echo 86400
    return
  fi
  local remaining=$((COST_DEADLINE_EPOCH - $(date +%s) - 300))
  if [ "$remaining" -lt 1 ]; then
    echo 0
  else
    echo "$remaining"
  fi
}

bounded_by_cost_deadline() {
  local requested="$1"
  shift
  local remaining
  remaining=$(seconds_remaining)
  if [ "$remaining" -le 0 ]; then
    echo "ERROR: cost deadline has no five-minute cleanup reserve" >&2
    return 124
  fi
  if [ "$requested" -gt "$remaining" ]; then
    requested="$remaining"
  fi
  run_bounded "$requested" "$@"
}

bounded_by_cost_deadline_with_reserve() {
  local requested="$1"
  local reserve_seconds="$2"
  shift 2
  if [ "$COST_DEADLINE_EPOCH" -eq 0 ]; then
    run_bounded "$requested" "$@"
    return
  fi
  local remaining=$((COST_DEADLINE_EPOCH - $(date +%s) - reserve_seconds))
  if [ "$remaining" -le 0 ]; then
    echo "ERROR: cost deadline cannot preserve the requested cleanup reserve" >&2
    return 124
  fi
  if [ "$requested" -gt "$remaining" ]; then
    requested="$remaining"
  fi
  run_bounded "$requested" "$@"
}

cost_timeout_with_reserve() {
  local requested="$1"
  local reserve_seconds="$2"
  if [ "$COST_DEADLINE_EPOCH" -eq 0 ]; then
    echo "$requested"
    return
  fi
  local remaining=$((COST_DEADLINE_EPOCH - $(date +%s) - reserve_seconds))
  if [ "$remaining" -le 0 ]; then
    return 124
  fi
  if [ "$requested" -gt "$remaining" ]; then
    requested="$remaining"
  fi
  echo "$requested"
}

for command in aws terraform jq git curl python3 ssh scp ssh-keygen tar sha256sum session-manager-plugin; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "ERROR: required local command not found: $command" >&2
    echo "Install every prerequisite before apply; no AWS resources were created." >&2
    exit 2
  fi
done
if [ ! -d "$COURSE_REPO/capstone/app" ] \
  || [ ! -f "$COURSE_REPO/capstone/solutions/validate-live.sh" ]; then
  echo "ERROR: COURSE_REPO does not contain the Day 5 live-validation harness" >&2
  exit 2
fi
if ! command -v "$BROWSER_PYTHON" >/dev/null 2>&1; then
  echo "ERROR: BROWSER_PYTHON command not found: $BROWSER_PYTHON" >&2
  exit 2
fi
case "$PLAYWRIGHT_BROWSER_CHANNEL" in
  chromium|chrome|msedge) ;;
  *)
    echo "ERROR: PLAYWRIGHT_BROWSER_CHANNEL must be chromium, chrome, or msedge" >&2
    exit 2
    ;;
esac
APPLY_STARTED=0
INSTANCE_ID=""
INSTANCE_TERMINATED=0
SSH_KEY_INSTALLED=0
DOWNLOAD_OK=0
PARTIAL_EVIDENCE=0
DESTROY_OK=0
RESIDUAL_OK=0
REMOTE_RC=99
REMOTE_REPORTED_RC=99
BROWSER_RC=99
FORWARDS_CLEANED=0
FORWARDS_STARTED=0
REMOTE_PROCESS_PID=0
PORT_FORWARD_PIDS=()
SSH_KEY="$WORK_DIR/live-validation-key"
SSH_PROXY=""

course_manifest() {
  python3 - \
    "$PINNED_COURSE" "$COURSE_REPO" "$COURSE_COMMIT" "$COURSE_TREE_HASH" \
    "$LOCAL_RUN_DIR/course-source.json" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
original = pathlib.Path(sys.argv[2]).resolve()
commit = sys.argv[3]
tree_hash_expected = sys.argv[4]
output = pathlib.Path(sys.argv[5])
capstone = root / "capstone"
files = {}
for path in sorted(capstone.rglob("*")):
    if path.is_file():
        files[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
tree_hash = hashlib.sha256(
    "".join(f"{name}\0{digest}\n" for name, digest in files.items()).encode()
).hexdigest()

document = {
    "schema": "owasp-llm-course-capstone-source/v1",
    "repository": str(original),
    "git_commit": commit,
    "git_tree": tree_hash_expected,
    "source": "git-archive",
    "capstone_content_sha256": tree_hash,
    "files": files,
}
output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remove_remote_key() {
  [ "$SSH_KEY_INSTALLED" -eq 1 ] || return 0
  [ -n "$INSTANCE_ID" ] || return 0
  local public_key
  public_key=$(<"$SSH_KEY.pub")
  local parameters="$WORK_DIR/remove-key.json"
  jq -n --arg key "$public_key" '{commands:[
    "if [ -f /home/ubuntu/.ssh/authorized_keys ]; then grep -vxF -- \"" + $key + "\" /home/ubuntu/.ssh/authorized_keys > /home/ubuntu/.ssh/authorized_keys.next || true; mv /home/ubuntu/.ssh/authorized_keys.next /home/ubuntu/.ssh/authorized_keys; chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys; chmod 600 /home/ubuntu/.ssh/authorized_keys; fi"
  ]}' >"$parameters"
  aws_cli ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name AWS-RunShellScript \
    --timeout-seconds 60 \
    --parameters "file://$parameters" \
    --output json >/dev/null 2>&1 || true
  SSH_KEY_INSTALLED=0
}

remote_scp() {
  bounded_by_cost_deadline 300 scp \
    -q -i "$SSH_KEY" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=15 \
    -o "ProxyCommand=$SSH_PROXY" \
    "$@"
}

remote_ssh() {
  bounded_by_cost_deadline 300 ssh \
    -i "$SSH_KEY" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=15 \
    -o ServerAliveInterval=15 \
    -o ServerAliveCountMax=4 \
    -o "ProxyCommand=$SSH_PROXY" \
    "ubuntu@$INSTANCE_ID" "$@"
}

download_remote_evidence() {
  [ "$DOWNLOAD_OK" -eq 0 ] || return 0
  [ "$SSH_KEY_INSTALLED" -eq 1 ] || return 1
  local attempt
  for attempt in 1 2 3; do
    if bounded_by_cost_deadline 180 scp \
      -q -i "$SSH_KEY" \
      -o BatchMode=yes \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=15 \
      -o "ProxyCommand=$SSH_PROXY" \
      "ubuntu@$INSTANCE_ID:$REMOTE_ARCHIVE" \
      "ubuntu@$INSTANCE_ID:$REMOTE_ARCHIVE_SHA" \
      "$LOCAL_REMOTE_DIR/"; then
      local archive_name sha_name expected actual
      archive_name=$(basename "$REMOTE_ARCHIVE")
      sha_name=$(basename "$REMOTE_ARCHIVE_SHA")
      expected=$(awk 'NR == 1 {print $1}' "$LOCAL_REMOTE_DIR/$sha_name")
      actual=$(sha256sum "$LOCAL_REMOTE_DIR/$archive_name" | awk '{print $1}')
      if [[ "$expected" =~ ^[0-9a-f]{64}$ ]] && [ "$expected" = "$actual" ]; then
        printf '%s  %s\n' "$actual" "$archive_name" \
          >"$LOCAL_REMOTE_DIR/$archive_name.local.sha256"
        DOWNLOAD_OK=1
        log "Evidence archive downloaded and SHA-256 verified"
        return 0
      fi
      log "Evidence download attempt $attempt had a SHA-256 mismatch"
    else
      log "Evidence download attempt $attempt failed"
    fi
    sleep 5
  done
  return 1
}

collect_fallback_evidence() {
  [ "$SSH_KEY_INSTALLED" -eq 1 ] || return 0
  if remote_ssh bash -s -- \
    "$REMOTE_RUN_ROOT" "$REMOTE_ARCHIVE" "$REMOTE_ARCHIVE_SHA" <<'REMOTE_PARTIAL'
set -euo pipefail
run_root="$1"
archive="$2"
archive_sha="$3"
test -d "$run_root"
archive_root=$(dirname "$archive")
mkdir -p "$archive_root"
jq -n --arg collected_at "$(date -Iseconds)" \
  '{schema:"owasp-llm-partial-evidence/v1",partial:true,collected_at:$collected_at,
    reason:"controller recovered run root after remote timeout/crash"}' \
  >"$run_root/controller-partial.json"
(
  cd "$run_root"
  find . -type f ! -name file-sha256.txt -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum >file-sha256.txt
)
temporary="$archive.controller-partial"
rm -f "$temporary" "$archive" "$archive_sha"
tar -C "$(dirname "$run_root")" -czf "$temporary" "$(basename "$run_root")"
mv "$temporary" "$archive"
(
  cd "$archive_root"
  sha256sum "$(basename "$archive")" >"$(basename "$archive_sha")"
)
chmod 0600 "$archive" "$archive_sha"
REMOTE_PARTIAL
  then
    PARTIAL_EVIDENCE=1
    if download_remote_evidence; then
      log "Partial remote run root was archived and downloaded before termination"
      return 0
    fi
  fi
  remote_ssh \
    'sudo tail -n 500 /var/log/user-data.log; sudo tail -n 1000 /var/log/owasp-llm-lab-install.log' \
    >"$LOCAL_REMOTE_DIR/fallback-instance.log" 2>&1 || true
  chmod 0600 "$LOCAL_REMOTE_DIR/fallback-instance.log" 2>/dev/null || true
}

stop_port_forwards() {
  local pid cleanup_ok=1
  for pid in "${PORT_FORWARD_PIDS[@]}"; do
    [ -n "$pid" ] || continue
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill -TERM "$pid" >/dev/null 2>&1 || true
    fi
  done
  for pid in "${PORT_FORWARD_PIDS[@]}"; do
    [ -n "$pid" ] || continue
    wait "$pid" >/dev/null 2>&1 || true
    if kill -0 "$pid" >/dev/null 2>&1; then
      cleanup_ok=0
      kill -KILL "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
  PORT_FORWARD_PIDS=()
  if ! python3 - <<'PY'
import socket

for port in (18011, 18501):
    sock = socket.socket()
    sock.settimeout(1)
    try:
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            raise SystemExit(1)
    finally:
        sock.close()
PY
  then
    cleanup_ok=0
  fi
  FORWARDS_CLEANED="$cleanup_ok"
  [ "$cleanup_ok" -eq 1 ]
}

stop_remote_process() {
  if [ "$REMOTE_PROCESS_PID" -gt 0 ] \
    && kill -0 "$REMOTE_PROCESS_PID" >/dev/null 2>&1; then
    kill -TERM "$REMOTE_PROCESS_PID" >/dev/null 2>&1 || true
    wait "$REMOTE_PROCESS_PID" >/dev/null 2>&1 || true
    sleep 3
  fi
  REMOTE_PROCESS_PID=0
}

start_port_forward() {
  local remote_port="$1"
  local local_port="$2"
  local label="$3"
  local log_file="$LOCAL_RUN_DIR/ssm-forward-$label.log"
  local forward_timeout
  forward_timeout=$(cost_timeout_with_reserve 1500 300) || return 124
  python3 "$BOUND_RUNNER" "$forward_timeout" \
    aws --profile "$AWS_PROFILE" --region "$AWS_REGION" \
      --no-cli-pager ssm start-session \
      --target "$INSTANCE_ID" \
      --document-name AWS-StartPortForwardingSession \
      --parameters "portNumber=[\"$remote_port\"],localPortNumber=[\"$local_port\"]" \
      </dev/null >"$log_file" 2>&1 &
  PORT_FORWARD_PIDS+=("$!")
  FORWARDS_STARTED=1
}

terminate_instances_direct() {
  local query_file="$WORK_DIR/terminate-query.json"
  local query_error="$WORK_DIR/terminate-query.err"
  local -a instance_ids=()
  local id seen existing captured_state captured_error

  if aws_cli ec2 describe-instances \
    --filters "Name=tag:Course,Values=$COURSE_ID" \
      "Name=instance-state-name,Values=pending,running,shutting-down,stopping,stopped" \
    --output json >"$query_file" 2>"$query_error"; then
    while IFS= read -r id; do
      [ -n "$id" ] && instance_ids+=("$id")
    done < <(jq -r '.Reservations[].Instances[]?.InstanceId' "$query_file")
  else
    cat "$query_error" >>"$CONTROL_LOG"
    return 1
  fi

  if [ -n "$INSTANCE_ID" ]; then
    seen=0
    for existing in "${instance_ids[@]}"; do
      [ "$existing" = "$INSTANCE_ID" ] && seen=1
    done
    if [ "$seen" -ne 1 ]; then
      captured_state="$WORK_DIR/captured-instance-state.txt"
      captured_error="$WORK_DIR/captured-instance-state.err"
      if aws_cli ec2 describe-instances --instance-ids "$INSTANCE_ID" \
        --query 'Reservations[0].Instances[0].State.Name' --output text \
        >"$captured_state" 2>"$captured_error"; then
        case "$(tr -d '\r\n' <"$captured_state")" in
          terminated) ;;
          pending|running|shutting-down|stopping|stopped)
            instance_ids+=("$INSTANCE_ID")
            ;;
          *) return 1 ;;
        esac
      elif ! grep -q 'InvalidInstanceID.NotFound' "$captured_error"; then
        cat "$captured_error" >>"$CONTROL_LOG"
        return 1
      fi
    fi
  fi

  if [ "${#instance_ids[@]}" -eq 0 ]; then
    INSTANCE_TERMINATED=1
    return 0
  fi

  log "Direct EC2 termination requested before Terraform network cleanup"
  aws_cli ec2 terminate-instances --instance-ids "${instance_ids[@]}" \
    --output json >>"$CONTROL_LOG" 2>&1 || {
      sleep 3
      aws_cli ec2 terminate-instances --instance-ids "${instance_ids[@]}" \
        --output json >>"$CONTROL_LOG" 2>&1 || return 1
    }

  local deadline=$(( $(date +%s) + 600 ))
  local all_terminated state_file state_error
  while [ "$(date +%s)" -lt "$deadline" ]; do
    all_terminated=1
    for id in "${instance_ids[@]}"; do
      state_file="$WORK_DIR/terminate-state-$id.txt"
      state_error="$WORK_DIR/terminate-state-$id.err"
      if aws_cli ec2 describe-instances --instance-ids "$id" \
        --query 'Reservations[0].Instances[0].State.Name' --output text \
        >"$state_file" 2>"$state_error"; then
        if [ "$(tr -d '\r\n' <"$state_file")" != "terminated" ]; then
          all_terminated=0
        fi
      elif ! grep -q 'InvalidInstanceID.NotFound' "$state_error"; then
        cat "$state_error" >>"$CONTROL_LOG"
        all_terminated=0
      fi
    done
    if [ "$all_terminated" -eq 1 ]; then
      INSTANCE_TERMINATED=1
      log "Direct EC2 termination is confirmed"
      return 0
    fi
    sleep 5
  done
  return 1
}

delete_validation_log_groups() {
  local prefix="/aws/lambda/owasp-llm-$COURSE_ID"
  local listing="$WORK_DIR/validation-log-groups.json"
  local group
  if ! aws_cli logs describe-log-groups --log-group-name-prefix "$prefix" \
    --output json >"$listing" 2>>"$CONTROL_LOG"; then
    return 1
  fi
  while IFS= read -r group; do
    [ -n "$group" ] || continue
    case "$group" in
      "$prefix"*)
        aws_cli logs delete-log-group --log-group-name "$group" \
          >>"$CONTROL_LOG" 2>&1 || return 1
        ;;
      *)
        echo "ERROR: refusing to delete unexpected log group: $group" \
          >>"$CONTROL_LOG"
        return 1
        ;;
    esac
  done < <(jq -r '.logGroups[]?.logGroupName' "$listing")
}

direct_residual_audit() {
  local audit_tmp="$WORK_DIR/residual"
  mkdir -p "$audit_tmp"
  local failed=0

  aws_cli ec2 describe-instances \
    --filters "Name=tag:Course,Values=$COURSE_ID" \
    --output json >"$audit_tmp/instances.json" 2>>"$CONTROL_LOG" || failed=1
  if [ -n "$INSTANCE_ID" ]; then
    aws_cli ec2 describe-instances --instance-ids "$INSTANCE_ID" \
      --output json >"$audit_tmp/instance-id.json" 2>>"$CONTROL_LOG" || failed=1
  else
    printf '{"Reservations":[]}' >"$audit_tmp/instance-id.json"
  fi
  aws_cli ec2 describe-volumes \
    --filters "Name=tag:Course,Values=$COURSE_ID" \
    --output json >"$audit_tmp/volumes.json" 2>>"$CONTROL_LOG" || failed=1
  aws_cli ec2 describe-network-interfaces \
    --filters "Name=tag:Course,Values=$COURSE_ID" \
    --output json >"$audit_tmp/enis.json" 2>>"$CONTROL_LOG" || failed=1
  if [ -n "$INSTANCE_ID" ]; then
    aws_cli ec2 describe-network-interfaces \
      --filters "Name=attachment.instance-id,Values=$INSTANCE_ID" \
      --output json >"$audit_tmp/instance-enis.json" 2>>"$CONTROL_LOG" || failed=1
  else
    printf '{"NetworkInterfaces":[]}' >"$audit_tmp/instance-enis.json"
  fi
  aws_cli ec2 describe-addresses \
    --filters "Name=tag:Course,Values=$COURSE_ID" \
    --output json >"$audit_tmp/eips.json" 2>>"$CONTROL_LOG" || failed=1
  aws_cli ec2 describe-vpcs \
    --filters "Name=tag:Course,Values=$COURSE_ID" \
    --output json >"$audit_tmp/vpcs.json" 2>>"$CONTROL_LOG" || failed=1
  aws_cli ec2 describe-subnets \
    --filters "Name=tag:Course,Values=$COURSE_ID" \
    --output json >"$audit_tmp/subnets.json" 2>>"$CONTROL_LOG" || failed=1
  aws_cli ec2 describe-security-groups \
    --filters "Name=tag:Course,Values=$COURSE_ID" \
    --output json >"$audit_tmp/security-groups.json" 2>>"$CONTROL_LOG" || failed=1
  aws_cli ec2 describe-route-tables \
    --filters "Name=tag:Course,Values=$COURSE_ID" \
    --output json >"$audit_tmp/route-tables.json" 2>>"$CONTROL_LOG" || failed=1
  aws_cli ec2 describe-internet-gateways \
    --filters "Name=tag:Course,Values=$COURSE_ID" \
    --output json >"$audit_tmp/internet-gateways.json" 2>>"$CONTROL_LOG" || failed=1
  aws_cli lambda list-functions --output json \
    >"$audit_tmp/lambda.json" 2>>"$CONTROL_LOG" || failed=1
  aws_cli events list-rules --output json \
    >"$audit_tmp/events.json" 2>>"$CONTROL_LOG" || failed=1
  aws_cli sns list-topics --output json \
    >"$audit_tmp/sns.json" 2>>"$CONTROL_LOG" || failed=1
  aws_cli logs describe-log-groups --output json \
    >"$audit_tmp/logs.json" 2>>"$CONTROL_LOG" || failed=1
  aws_cli iam list-roles --output json \
    >"$audit_tmp/roles.json" 2>>"$CONTROL_LOG" || failed=1
  aws_cli iam list-instance-profiles --output json \
    >"$audit_tmp/profiles.json" 2>>"$CONTROL_LOG" || failed=1

  local account_id
  account_id=$(aws_cli sts get-caller-identity --query Account --output text 2>>"$CONTROL_LOG") \
    || failed=1
  if [ -n "${account_id:-}" ]; then
    aws_cli budgets describe-budgets --account-id "$account_id" --output json \
      >"$audit_tmp/budgets.json" 2>>"$CONTROL_LOG" || failed=1
  else
    printf '{"Budgets":[]}' >"$audit_tmp/budgets.json"
  fi

  if [ "$failed" -ne 0 ]; then
    jq -n --arg course_id "$COURSE_ID" \
      '{schema:"owasp-llm-residual-audit/v1",course_id:$course_id,
        status:"INCOMPLETE",reason:"one or more direct AWS queries failed"}' \
      >"$RESIDUAL_REPORT"
    return 1
  fi

  jq -n \
    --arg course_id "$COURSE_ID" \
    --slurpfile instances "$audit_tmp/instances.json" \
    --slurpfile instance_id "$audit_tmp/instance-id.json" \
    --slurpfile volumes "$audit_tmp/volumes.json" \
    --slurpfile enis "$audit_tmp/enis.json" \
    --slurpfile instance_enis "$audit_tmp/instance-enis.json" \
    --slurpfile eips "$audit_tmp/eips.json" \
    --slurpfile vpcs "$audit_tmp/vpcs.json" \
    --slurpfile subnets "$audit_tmp/subnets.json" \
    --slurpfile security_groups "$audit_tmp/security-groups.json" \
    --slurpfile route_tables "$audit_tmp/route-tables.json" \
    --slurpfile internet_gateways "$audit_tmp/internet-gateways.json" \
    --slurpfile lambda "$audit_tmp/lambda.json" \
    --slurpfile events "$audit_tmp/events.json" \
    --slurpfile sns "$audit_tmp/sns.json" \
    --slurpfile logs "$audit_tmp/logs.json" \
    --slurpfile roles "$audit_tmp/roles.json" \
    --slurpfile profiles "$audit_tmp/profiles.json" \
    --slurpfile budgets "$audit_tmp/budgets.json" '
      def includes_course: contains($course_id);
      {
        schema:"owasp-llm-residual-audit/v1", course_id:$course_id,
        checked_at:(now | todateiso8601),
        counts:{
          active_instances:([$instances[0].Reservations[].Instances[]?
            | select(.State.Name != "terminated")] | length),
          active_instance_id:([$instance_id[0].Reservations[].Instances[]?
            | select(.State.Name != "terminated")] | length),
          volumes:($volumes[0].Volumes | length),
          network_interfaces:($enis[0].NetworkInterfaces | length),
          instance_network_interfaces:($instance_enis[0].NetworkInterfaces | length),
          elastic_ips:($eips[0].Addresses | length),
          vpcs:($vpcs[0].Vpcs | length),
          subnets:($subnets[0].Subnets | length),
          security_groups:($security_groups[0].SecurityGroups | length),
          route_tables:($route_tables[0].RouteTables | length),
          internet_gateways:($internet_gateways[0].InternetGateways | length),
          lambda_functions:([$lambda[0].Functions[]?
            | select(.FunctionName | includes_course)] | length),
          event_rules:([$events[0].Rules[]?
            | select(.Name | includes_course)] | length),
          sns_topics:([$sns[0].Topics[]?
            | select(.TopicArn | includes_course)] | length),
          log_groups:([$logs[0].logGroups[]?
            | select(.logGroupName | includes_course)] | length),
          iam_roles:([$roles[0].Roles[]?
            | select(.RoleName | includes_course)] | length),
          instance_profiles:([$profiles[0].InstanceProfiles[]?
            | select(.InstanceProfileName | includes_course)] | length),
          budgets:([$budgets[0].Budgets[]?
            | select(.BudgetName | includes_course)] | length)
        }
      }
      | .status = (if ([.counts[]] | add) == 0 then "PASS" else "FAIL" end)
    ' >"$RESIDUAL_REPORT"
  jq -e '.status == "PASS"' "$RESIDUAL_REPORT" >/dev/null
}

cleanup() {
  local original_rc=$?
  trap - EXIT
  trap 'log "Cleanup signal received; mandatory destroy/audit continues"' HUP INT TERM
  set +e

  if [ "$APPLY_STARTED" -eq 1 ]; then
    stop_port_forwards || true
    stop_remote_process
    if [ "$DOWNLOAD_OK" -eq 0 ]; then
      download_remote_evidence || collect_fallback_evidence
    fi
    remove_remote_key

    if ! terminate_instances_direct; then
      log "Direct EC2 termination was not yet confirmed; Terraform destroy proceeds"
    fi

    log "Terraform destroy started (mandatory EXIT trap)"
    if run_bounded 1200 terraform -chdir="$TF_DIR" destroy \
      -auto-approve -input=false -no-color -lock-timeout=60s "${TF_VARS[@]}" \
      >>"$CONTROL_LOG" 2>&1; then
      remaining_state=""
      if remaining_state=$(terraform -chdir="$TF_DIR" state list 2>>"$CONTROL_LOG") \
        && [ -z "$remaining_state" ]; then
        DESTROY_OK=1
        log "Terraform destroy completed and state is empty"
      fi
    fi
    if [ "$DESTROY_OK" -ne 1 ]; then
      log "First destroy verification failed; one bounded retry follows"
      run_bounded 1200 terraform -chdir="$TF_DIR" destroy \
        -auto-approve -input=false -no-color -lock-timeout=60s "${TF_VARS[@]}" \
        >>"$CONTROL_LOG" 2>&1 || true
      remaining_state=""
      if remaining_state=$(terraform -chdir="$TF_DIR" state list 2>>"$CONTROL_LOG") \
        && [ -z "$remaining_state" ]; then
        DESTROY_OK=1
      fi
    fi

    # A provider/network failure must never leave the expensive instance alive.
    # Re-query by both captured ID and unique Course tag after destroy/retry.
    if ! terminate_instances_direct; then
      log "Direct EC2 termination retry did not reach terminated state"
    fi
    if ! delete_validation_log_groups; then
      log "Validation Lambda log-group cleanup did not complete"
    fi

    if direct_residual_audit; then
      RESIDUAL_OK=1
      log "Direct AWS residual audit passed"
    else
      log "Direct AWS residual audit did not pass; inspect $RESIDUAL_REPORT"
    fi
  fi

  rm -rf "$WORK_DIR"
  if [ "$APPLY_STARTED" -eq 1 ] \
    && { [ "$INSTANCE_TERMINATED" -ne 1 ] \
      || [ "$DESTROY_OK" -ne 1 ] || [ "$RESIDUAL_OK" -ne 1 ]; }; then
    original_rc=1
  fi
  if [ "$APPLY_STARTED" -eq 1 ] && [ "$DOWNLOAD_OK" -ne 1 ]; then
    original_rc=1
  fi
  if [ "$FORWARDS_STARTED" -eq 1 ] && [ "$FORWARDS_CLEANED" -ne 1 ]; then
    original_rc=1
  fi

  jq -n \
    --arg run_id "$RUN_ID" \
    --arg setup_commit "$SETUP_COMMIT" \
    --arg image_registry "$IMAGE_REGISTRY" \
    --arg image_namespace "$IMAGE_NAMESPACE" \
    --arg image_tag "$IMAGE_TAG" \
    --arg course_id "$COURSE_ID" \
    --arg course_commit "$COURSE_COMMIT" \
    --arg course_tree_hash "$COURSE_TREE_HASH" \
    --arg setup_tree_hash "$SETUP_TREE_HASH" \
    --arg terraform_tree_hash "$TERRAFORM_TREE_HASH" \
    --argjson remote_rc "$REMOTE_RC" \
    --argjson remote_reported_rc "$REMOTE_REPORTED_RC" \
    --argjson browser_rc "$BROWSER_RC" \
    --argjson forwards_cleaned "$FORWARDS_CLEANED" \
    --argjson download_ok "$DOWNLOAD_OK" \
    --argjson partial_evidence "$PARTIAL_EVIDENCE" \
    --argjson destroy_ok "$DESTROY_OK" \
    --argjson instance_terminated "$INSTANCE_TERMINATED" \
    --argjson residual_ok "$RESIDUAL_OK" \
    '{schema:"owasp-llm-controller-result/v1",run_id:$run_id,
      setup_commit:$setup_commit,image_registry:$image_registry,
      image_namespace:$image_namespace,
      image_tag:$image_tag,course_id:$course_id,remote_rc:$remote_rc,
      remote_reported_rc:$remote_reported_rc,
      course_commit:$course_commit,course_tree_hash:$course_tree_hash,
      browser_rc:$browser_rc,ssm_forwards_cleaned:($forwards_cleaned == 1),
      setup_tree_hash:$setup_tree_hash,terraform_tree_hash:$terraform_tree_hash,
      evidence_downloaded:($download_ok == 1),partial_evidence:($partial_evidence == 1),
      terraform_destroyed:($destroy_ok == 1),
      direct_instance_terminated:($instance_terminated == 1),
      residual_audit_passed:($residual_ok == 1)}' \
    >"$LOCAL_RUN_DIR/controller-result.json"

  if [ "$APPLY_STARTED" -eq 1 ]; then
    log "Final safety status: evidence=$DOWNLOAD_OK instance_terminated=$INSTANCE_TERMINATED destroy=$DESTROY_OK residual=$RESIDUAL_OK"
  fi
  trap - HUP INT TERM
  exit "$original_rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

log "Preflight started; no AWS resources exist yet"

run_bounded 120 git -C "$REPO_ROOT" fetch --quiet origin main
if ! git -C "$REPO_ROOT" cat-file -e "$SETUP_COMMIT^{commit}" \
  || ! git -C "$REPO_ROOT" merge-base --is-ancestor "$SETUP_COMMIT" origin/main; then
  echo "ERROR: SETUP_COMMIT is not a published origin/main commit" >&2
  exit 1
fi
for required_path in \
  infrastructure/scripts/instructor/run-commit-live-validation.sh \
  infrastructure/scripts/instructor/run-bounded-command.py \
  infrastructure/scripts/instructor/resolve-image-digests.py \
  infrastructure/scripts/instructor/run-remote-validation.sh \
  infrastructure/scripts/student/upload-capstone.sh \
  tests/browser/run_day3_ui.py \
  tests/browser/day3_ui_helpers.py \
  tests/browser/requirements.txt \
  docker/vuln-rag/app/scenarios/day4.py \
  tests/e2e/run-full-cycle.sh \
  tests/e2e/llm09/run-isolated-slopsquat.sh; do
  if ! git -C "$REPO_ROOT" cat-file -e "$SETUP_COMMIT:$required_path"; then
    echo "ERROR: SETUP_COMMIT does not contain $required_path" >&2
    exit 1
  fi
done

run_bounded 120 git -C "$COURSE_REPO" fetch --quiet origin main
course_status=$(git -C "$COURSE_REPO" status --porcelain=v1 --untracked-files=all)
if [ -n "$course_status" ]; then
  echo "ERROR: COURSE_REPO must be completely clean before paid validation" >&2
  printf '%s\n' "$course_status" >&2
  exit 1
fi
if [ "$(git -C "$COURSE_REPO" rev-parse HEAD)" != "$COURSE_COMMIT" ] \
  || ! git -C "$COURSE_REPO" cat-file -e "$COURSE_COMMIT^{commit}" \
  || ! git -C "$COURSE_REPO" merge-base --is-ancestor "$COURSE_COMMIT" origin/main; then
  echo "ERROR: COURSE_REPO must be at the explicit published COURSE_COMMIT" >&2
  exit 1
fi
for controller_path in \
  infrastructure/scripts/instructor/run-commit-live-validation.sh \
  infrastructure/scripts/instructor/run-bounded-command.py \
  infrastructure/scripts/instructor/resolve-image-digests.py \
  infrastructure/scripts/instructor/run-remote-validation.sh \
  infrastructure/scripts/student/upload-capstone.sh \
  tests/browser/run_day3_ui.py \
  tests/browser/day3_ui_helpers.py; do
  committed_blob=$(git -C "$REPO_ROOT" rev-parse "$SETUP_COMMIT:$controller_path")
  local_blob=$(git -C "$REPO_ROOT" hash-object "$controller_path")
  if [ "$local_blob" != "$committed_blob" ]; then
    echo "ERROR: local controller dependency differs from SETUP_COMMIT: $controller_path" >&2
    exit 1
  fi
done

mkdir -p "$PINNED_REPO"
git -C "$REPO_ROOT" archive --format=tar "$SETUP_COMMIT" \
  >"$WORK_DIR/pinned-setup.tar"
tar -xf "$WORK_DIR/pinned-setup.tar" -C "$PINNED_REPO"
rm -f "$WORK_DIR/pinned-setup.tar"
SETUP_TREE_HASH=$(git -C "$REPO_ROOT" rev-parse "$SETUP_COMMIT^{tree}")
TERRAFORM_TREE_HASH=$(git -C "$REPO_ROOT" rev-parse \
  "$SETUP_COMMIT:infrastructure/terraform")
jq -n \
  --arg setup_commit "$SETUP_COMMIT" \
  --arg setup_tree_hash "$SETUP_TREE_HASH" \
  --arg terraform_tree_hash "$TERRAFORM_TREE_HASH" \
  --arg terraform_dir "$TF_DIR" \
  '{schema:"owasp-llm-pinned-setup-source/v1",setup_commit:$setup_commit,
    setup_tree_hash:$setup_tree_hash,terraform_tree_hash:$terraform_tree_hash,
    terraform_dir:$terraform_dir}' \
  >"$LOCAL_RUN_DIR/pinned-setup-source.json"

if [ ! -d "$TF_DIR" ]; then
  echo "ERROR: pinned commit has no Terraform directory" >&2
  exit 1
fi

mkdir -p "$PINNED_COURSE"
git -C "$COURSE_REPO" archive --format=tar "$COURSE_COMMIT" capstone \
  >"$WORK_DIR/pinned-course.tar"
tar -xf "$WORK_DIR/pinned-course.tar" -C "$PINNED_COURSE"
rm -f "$WORK_DIR/pinned-course.tar"
COURSE_TREE_HASH=$(git -C "$COURSE_REPO" rev-parse "$COURSE_COMMIT^{tree}")
if [ ! -f "$PINNED_COURSE/capstone/solutions/validate-live.sh" ]; then
  echo "ERROR: published COURSE_COMMIT lacks the Day 5 live harness" >&2
  exit 1
fi
course_manifest

if ! grep -Fq "$LLM09_FIXTURE_PACKAGE" \
  "$PINNED_REPO/docker/vuln-rag/app/scenarios/day4.py"; then
  echo "ERROR: pinned Day 4 scenario lacks the deterministic LLM09 package fixture" >&2
  exit 1
fi

required_playwright=$(awk -F= '$1 == "playwright" {print $3}' \
  "$PINNED_REPO/tests/browser/requirements.txt")
installed_playwright=$("$BROWSER_PYTHON" -c \
  'import importlib.metadata; print(importlib.metadata.version("playwright"))' \
  2>/dev/null || true)
if [ -z "$required_playwright" ] || [ "$installed_playwright" != "$required_playwright" ]; then
  echo "ERROR: browser preflight requires playwright==$required_playwright (installed: ${installed_playwright:-missing})" >&2
  echo "Install the pinned tests/browser/requirements.txt before creating EC2." >&2
  exit 1
fi
run_bounded 60 "$BROWSER_PYTHON" - "$PLAYWRIGHT_BROWSER_CHANNEL" <<'PY'
import socket
import sys
from playwright.sync_api import sync_playwright

channel = sys.argv[1]
for port in (18011, 18501):
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", port))
    except OSError as exc:
        raise SystemExit(f"local browser-forward port {port} is unavailable: {exc}")
    finally:
        sock.close()

with sync_playwright() as playwright:
    options = {"headless": True}
    if channel != "chromium":
        options["channel"] = channel
    browser = playwright.chromium.launch(**options)
    browser.close()
PY
log "Local Playwright/browser/port preflight passed before AWS apply"

llm09_fixture_status=$(curl -sS -L -o /dev/null --max-time 15 \
  -w '%{http_code}' \
  "https://pypi.org/simple/$LLM09_FIXTURE_PACKAGE/" || true)
case "$llm09_fixture_status" in
  404|410) ;;
  *)
    echo "ERROR: deterministic LLM09 fixture is not currently PyPI NOT_FOUND (HTTP ${llm09_fixture_status:-transport-error})" >&2
    exit 1
    ;;
esac
jq -n \
  --arg package "$LLM09_FIXTURE_PACKAGE" \
  --argjson http_status "$llm09_fixture_status" \
  --arg checked_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{package:$package,http_status:$http_status,classification:"NOT_FOUND",
    checked_at:$checked_at}' >"$LOCAL_RUN_DIR/llm09-fixture-preflight.json"
log "LLM09 deterministic package fixture is currently PyPI NOT_FOUND"

log "Resolving all five immutable GHCR tag/platform digests"
run_bounded 180 python3 "$PINNED_REPO/infrastructure/scripts/instructor/resolve-image-digests.py" \
  --registry "$IMAGE_REGISTRY" \
  --namespace "$IMAGE_NAMESPACE" \
  --tag "$IMAGE_TAG" \
  --output "$DIGEST_MANIFEST"
jq -e '.images | length == 5' "$DIGEST_MANIFEST" >/dev/null

run_bounded 60 aws \
  --profile "$AWS_PROFILE" --region "$AWS_REGION" --no-cli-pager \
  --cli-connect-timeout 5 --cli-read-timeout 30 \
  sts get-caller-identity --output json >/dev/null

log "Initializing Terraform and asserting an empty state"
run_bounded 300 terraform -chdir="$TF_DIR" init -input=false -no-color \
  >>"$CONTROL_LOG" 2>&1
run_bounded 120 terraform -chdir="$TF_DIR" validate -no-color \
  >>"$CONTROL_LOG" 2>&1
existing_state=$(terraform -chdir="$TF_DIR" state list)
if [ -n "$existing_state" ]; then
  echo "ERROR: Terraform state is not empty; refusing to mix or destroy existing resources" >&2
  printf '%s\n' "$existing_state" >&2
  exit 1
fi

schedule_document=$(python3 - "$EMERGENCY_STOP_MINUTES" <<'PY'
from datetime import datetime, timedelta, timezone
import json
import sys

now = datetime.now(timezone.utc)
stop = now + timedelta(minutes=int(sys.argv[1]))
dates = [(now.date() + timedelta(days=offset)).isoformat() for offset in range(5)]
print(json.dumps({
    "deadline_epoch": int(stop.timestamp()),
    "cron": f"cron({stop.minute} {stop.hour} {stop.day} {stop.month} ? {stop.year})",
    "course_dates": dates,
}, separators=(",", ":")))
PY
)
COST_DEADLINE_EPOCH=$(jq -er '.deadline_epoch' <<<"$schedule_document")
EMERGENCY_CRON=$(jq -er '.cron' <<<"$schedule_document")
COURSE_DATES_JSON=$(jq -cer '.course_dates' <<<"$schedule_document")

export TF_IN_AUTOMATION=1
export TF_VAR_alert_email="$ALERT_EMAIL"
TF_VARS=(
  "-var=region=$AWS_REGION"
  "-var=aws_profile=$AWS_PROFILE"
  "-var=course_id=$COURSE_ID"
  "-var=student_ids=[\"$STUDENT\"]"
  "-var=course_dates=$COURSE_DATES_JSON"
  "-var=enable_user_data_bootstrap=true"
  "-var=lab_setup_repo_raw_url=https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/$SETUP_COMMIT"
  "-var=lab_image_namespace=$IMAGE_NAMESPACE"
  "-var=lab_image_tag=$IMAGE_TAG"
  "-var=allowed_ingress_cidr=127.0.0.1/32"
  "-var=enable_auto_stop=true"
  "-var=auto_stop_schedule_mode=custom"
  "-var=auto_stop_custom_crons_utc={\"validation-emergency\":\"$EMERGENCY_CRON\"}"
  "-var=auto_stop_description=Instructor live validation emergency stop"
  "-var=daily_budget_usd=5"
  "-var=course_budget_usd=10"
)

log "Terraform apply starts; emergency stop is $EMERGENCY_CRON"
APPLY_STARTED=1
bounded_by_cost_deadline 1200 terraform -chdir="$TF_DIR" apply \
  -auto-approve -input=false -no-color -lock-timeout=60s "${TF_VARS[@]}" \
  >>"$CONTROL_LOG" 2>&1

if ! terraform -chdir="$TF_DIR" output -json auto_stop_schedule \
  | jq -e --arg expected "$EMERGENCY_CRON" \
      'length == 1 and .["validation-emergency"] == $expected' >/dev/null; then
  echo "ERROR: Terraform output does not prove the emergency auto-stop schedule" >&2
  exit 1
fi
INSTANCE_ID=$(terraform -chdir="$TF_DIR" output -json instance_ids \
  | jq -er --arg student "$STUDENT" '.[$student]')
if [[ ! "$INSTANCE_ID" =~ ^i-[0-9a-f]+$ ]]; then
  echo "ERROR: invalid instance id from Terraform output" >&2
  exit 1
fi
log "Apply complete; waiting for the single EC2 and SSM within bounded deadlines"

ready=0
for _ in $(seq 1 90); do
  state=$(aws_cli ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || true)
  if [ "$state" = "running" ]; then
    ready=1
    break
  fi
  [ "$(seconds_remaining)" -gt 0 ] || break
  sleep 5
done
if [ "$ready" -ne 1 ]; then
  echo "ERROR: EC2 did not reach running before the bounded deadline" >&2
  exit 1
fi

ssm_online=0
for _ in $(seq 1 180); do
  ping=$(aws_cli ssm describe-instance-information \
    --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
    --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)
  if [ "$ping" = "Online" ]; then
    ssm_online=1
    break
  fi
  [ "$(seconds_remaining)" -gt 0 ] || break
  sleep 5
done
if [ "$ssm_online" -ne 1 ]; then
  echo "ERROR: SSM did not become Online before the bounded deadline" >&2
  exit 1
fi

ssh-keygen -q -t ed25519 -N '' -C "owasp-live-$RUN_ID" -f "$SSH_KEY"
public_key=$(<"$SSH_KEY.pub")
install_parameters="$WORK_DIR/install-key.json"
jq -n --arg key "$public_key" '{commands:[
  "install -d -m 700 -o ubuntu -g ubuntu /home/ubuntu/.ssh",
  "touch /home/ubuntu/.ssh/authorized_keys",
  "grep -qxF -- \"" + $key + "\" /home/ubuntu/.ssh/authorized_keys || echo \"" + $key + "\" >> /home/ubuntu/.ssh/authorized_keys",
  "chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys",
  "chmod 600 /home/ubuntu/.ssh/authorized_keys"
]}' >"$install_parameters"
command_id=$(aws_cli ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name AWS-RunShellScript \
  --timeout-seconds 120 \
  --parameters "file://$install_parameters" \
  --query 'Command.CommandId' --output text)
command_ok=0
for _ in $(seq 1 36); do
  status=$(aws_cli ssm get-command-invocation \
    --command-id "$command_id" --instance-id "$INSTANCE_ID" \
    --query Status --output text 2>/dev/null || true)
  case "$status" in
    Success) command_ok=1; break ;;
    Failed|Cancelled|TimedOut|Cancelling) break ;;
  esac
  sleep 5
done
if [ "$command_ok" -ne 1 ]; then
  echo "ERROR: temporary SSM SSH authorization failed" >&2
  exit 1
fi
SSH_KEY_INSTALLED=1
SSH_PROXY="aws ssm start-session --profile $AWS_PROFILE --region $AWS_REGION --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p"

log "Waiting for commit-pinned user-data bootstrap"
bounded_by_cost_deadline 4500 ssh \
  -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
  -o "ProxyCommand=$SSH_PROXY" "ubuntu@$INSTANCE_ID" \
  'sudo cloud-init status --wait' >>"$CONTROL_LOG" 2>&1

remote_ssh bash -s -- "$SETUP_COMMIT" "$SETUP_GIT_URL" "$REMOTE_REPO" <<'REMOTE_SETUP'
set -euo pipefail
commit="$1"
git_url="$2"
destination="$3"
rm -rf "$destination"
git clone --quiet --filter=blob:none --no-checkout "$git_url" "$destination"
git -C "$destination" fetch --quiet --depth=1 origin "$commit"
git -C "$destination" checkout --quiet --detach "$commit"
test "$(git -C "$destination" rev-parse HEAD)" = "$commit"
REMOTE_SETUP

log "Uploading Day 5 course capstone with the existing setup uploader"
(
  cd "$PINNED_COURSE"
  AWS_PROFILE="$AWS_PROFILE" AWS_REGION="$AWS_REGION" STUDENT="$STUDENT" \
    TF_DIR="$TF_DIR" \
    bounded_by_cost_deadline 600 \
      bash "$PINNED_REPO/infrastructure/scripts/student/upload-capstone.sh"
) >>"$CONTROL_LOG" 2>&1

remote_scp "$DIGEST_MANIFEST" "ubuntu@$INSTANCE_ID:$REMOTE_DIGESTS"

log "Running strict full-cycle, isolated LLM09, and Day 5 reference harness"
# Leave ten minutes on the paid-resource clock for archive transfer before the
# emergency stop. Terraform destroy still runs even if that stop fires first.
remote_timeout=$(cost_timeout_with_reserve 7000 300) || {
  echo "ERROR: insufficient paid-resource deadline for remote validation" >&2
  exit 1
}
python3 "$BOUND_RUNNER" "$remote_timeout" ssh \
  -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
  -o "ProxyCommand=$SSH_PROXY" "ubuntu@$INSTANCE_ID" \
  "env SETUP_COMMIT=$SETUP_COMMIT IMAGE_REGISTRY=$IMAGE_REGISTRY IMAGE_NAMESPACE=$IMAGE_NAMESPACE IMAGE_TAG=$IMAGE_TAG EXPECTED_DIGESTS_FILE=$REMOTE_DIGESTS RUN_ID=$RUN_ID BROWSER_HANDOFF_DEADLINE_EPOCH=$((COST_DEADLINE_EPOCH - 300)) COURSE_CAPSTONE_DIR=/home/ubuntu/work/my-capstone bash $REMOTE_REPO/infrastructure/scripts/instructor/run-remote-validation.sh" \
  >"$LOCAL_RUN_DIR/remote-run.log" 2>&1 &
REMOTE_PROCESS_PID=$!

browser_ready=0
browser_ready_poll_deadline=$((COST_DEADLINE_EPOCH - 1500))
while [ "$(date +%s)" -lt "$browser_ready_poll_deadline" ]; do
  if grep -Fq "BROWSER_READY run_id=$RUN_ID " \
    "$LOCAL_RUN_DIR/remote-run.log" 2>/dev/null; then
    browser_ready=1
    break
  fi
  if ! kill -0 "$REMOTE_PROCESS_PID" >/dev/null 2>&1; then
    set +e
    wait "$REMOTE_PROCESS_PID"
    REMOTE_REPORTED_RC=$?
    set -e
    REMOTE_PROCESS_PID=0
    log "Remote validation exited before the browser hand-off (reported_rc=$REMOTE_REPORTED_RC)"
    download_remote_evidence || true
    # The browser-ready marker is part of the controller contract. Even an
    # impossible-looking zero from the remote process must fail closed here.
    REMOTE_RC=1
    BROWSER_RC=1
    exit 1
  fi
  sleep 5
done
if [ "$browser_ready" -ne 1 ]; then
  echo "ERROR: remote validation did not expose the bounded browser hand-off" >&2
  BROWSER_RC=1
  stop_remote_process
  exit 1
fi

log "Remote core tests completed; opening two bounded SSM browser forwards"
start_port_forward 8011 18011 rag
start_port_forward 8501 18501 dvla

forward_ready=0
for _ in $(seq 1 90); do
  forward_children_alive=1
  for pid in "${PORT_FORWARD_PIDS[@]}"; do
    kill -0 "$pid" >/dev/null 2>&1 || forward_children_alive=0
  done
  if [ "$forward_children_alive" -ne 1 ]; then
    break
  fi
  if curl --noproxy '*' -fsS --max-time 3 \
      http://127.0.0.1:18011/healthz 2>/dev/null \
      | jq -e '.ok == true and .default_scenario == "day3"' >/dev/null \
    && curl --noproxy '*' -fsS --max-time 3 \
      http://127.0.0.1:18501/_stcore/health 2>/dev/null \
      | grep -qx ok; then
    forward_ready=1
    break
  fi
  sleep 2
done

BROWSER_RESULT_DIR="$LOCAL_RUN_DIR/browser-evidence"
BROWSER_LOG="$LOCAL_RUN_DIR/browser-run.log"
if [ "$forward_ready" -eq 1 ]; then
  log "SSM forward health passed; running mandatory Day 3 UI/DVLA browser harness"
  set +e
  bounded_by_cost_deadline_with_reserve 1100 900 \
    "$BROWSER_PYTHON" "$PINNED_REPO/tests/browser/run_day3_ui.py" \
      --rag-url http://127.0.0.1:18011 \
      --dvla-url http://127.0.0.1:18501 \
      --browser-channel "$PLAYWRIGHT_BROWSER_CHANNEL" \
      --result-dir "$BROWSER_RESULT_DIR" \
      >"$BROWSER_LOG" 2>&1
  BROWSER_RC=$?
  set -e
else
  BROWSER_RC=1
  mkdir -p "$BROWSER_RESULT_DIR"
  printf '%s\n' "SSM port-forward health or child-process check failed" \
    >"$BROWSER_RESULT_DIR/preflight-error.txt"
  jq -n \
    '{schema_version:1,status:"FAIL",error:{type:"ForwardPreflightError",
      message:"SSM port-forward health or child-process check failed"},
      cleanup:{status:"NOT_RUN",browser_closed:false,receiver_closed:false}}' \
    >"$BROWSER_RESULT_DIR/result.json"
  preflight_sha=$(sha256sum "$BROWSER_RESULT_DIR/preflight-error.txt" | awk '{print $1}')
  jq -n --arg sha "$preflight_sha" '{"preflight-error.txt":$sha}' \
    >"$BROWSER_RESULT_DIR/sha256sums.json"
fi

stop_port_forwards || BROWSER_RC=1
cp "$LOCAL_RUN_DIR/ssm-forward-rag.log" \
  "$BROWSER_RESULT_DIR/ssm-forward-rag.log" 2>/dev/null || true
cp "$LOCAL_RUN_DIR/ssm-forward-dvla.log" \
  "$BROWSER_RESULT_DIR/ssm-forward-dvla.log" 2>/dev/null || true
cp "$BROWSER_LOG" "$BROWSER_RESULT_DIR/browser-run.log" 2>/dev/null || true

if [ ! -f "$BROWSER_RESULT_DIR/result.json" ]; then
  BROWSER_RC=1
fi
python3 - "$BROWSER_RESULT_DIR" "$BROWSER_RC" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
browser_rc = int(sys.argv[2])
root.mkdir(parents=True, exist_ok=True)
result_path = root / "result.json"
manifest_path = root / "sha256sums.json"
if not result_path.is_file():
    (root / "controller-synthetic-failure.txt").write_text(
        "Browser process returned without a result.json; controller synthesized FAIL evidence.\n",
        encoding="utf-8",
    )
    result = {
        "schema_version": 1,
        "status": "FAIL",
        "error": {
            "type": "MissingBrowserResult",
            "message": "browser process returned without result.json",
        },
        "cleanup": {
            "status": "NOT_PROVEN",
            "browser_closed": False,
            "receiver_closed": False,
        },
    }
else:
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        (root / "controller-synthetic-failure.txt").write_text(
            "Browser result.json was unreadable; controller synthesized FAIL evidence.\n",
            encoding="utf-8",
        )
        result = {
            "schema_version": 1,
            "status": "FAIL",
            "error": {
                "type": "InvalidBrowserResult",
                "message": "browser result.json was unreadable",
            },
            "cleanup": {"status": "NOT_PROVEN"},
        }

excluded = {"result.json", "sha256sums.json"}
manifest = {
    str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted(root.rglob("*"))
    if path.is_file() and path.name not in excluded
}
if not manifest:
    note = root / "controller-evidence-note.txt"
    note.write_text(f"browser_rc={browser_rc}\n", encoding="utf-8")
    manifest[note.name] = hashlib.sha256(note.read_bytes()).hexdigest()
manifest_path.write_text(
    json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
result["evidence_file_count"] = len(manifest)
result["sha256_manifest_sha256"] = hashlib.sha256(
    manifest_path.read_bytes()
).hexdigest()
temporary = root / "result.json.controller-next"
temporary.write_text(
    json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
temporary.replace(result_path)
PY
if [ "$BROWSER_RC" -eq 0 ] \
  && ! jq -e '.status == "PASS" and .cleanup.status == "PASS"' \
    "$BROWSER_RESULT_DIR/result.json" >/dev/null; then
  BROWSER_RC=1
fi

forward_cleanup_status=FAIL
[ "$FORWARDS_CLEANED" -eq 1 ] && forward_cleanup_status=PASS
result_sha=$(sha256sum "$BROWSER_RESULT_DIR/result.json" | awk '{print $1}')
manifest_sha=$(sha256sum "$BROWSER_RESULT_DIR/sha256sums.json" | awk '{print $1}')
BROWSER_CONTROL="$LOCAL_RUN_DIR/browser-controller-result.json"
jq -n \
  --argjson browser_rc "$BROWSER_RC" \
  --arg forward_cleanup "$forward_cleanup_status" \
  --arg result_sha "$result_sha" \
  --arg manifest_sha "$manifest_sha" \
  '{schema:"owasp-llm-browser-controller/v1",browser_rc:$browser_rc,
    forward_cleanup:$forward_cleanup,result_sha256:$result_sha,
    manifest_sha256:$manifest_sha}' >"$BROWSER_CONTROL"

remote_scp -r "$BROWSER_RESULT_DIR" \
  "ubuntu@$INSTANCE_ID:$REMOTE_RUN_ROOT/browser-evidence"
# Upload the coordination record last: its presence releases the remote archive.
remote_scp "$BROWSER_CONTROL" \
  "ubuntu@$INSTANCE_ID:$REMOTE_RUN_ROOT/browser-controller-result.json.partial"
remote_ssh mv \
  "$REMOTE_RUN_ROOT/browser-controller-result.json.partial" \
  "$REMOTE_RUN_ROOT/browser-controller-result.json"

set +e
wait "$REMOTE_PROCESS_PID"
REMOTE_RC=$?
REMOTE_REPORTED_RC=$REMOTE_RC
set -e
REMOTE_PROCESS_PID=0
log "Remote validation and browser archive phase finished (rc=$REMOTE_RC, browser_rc=$BROWSER_RC)"

download_remote_evidence
if [ "$DOWNLOAD_OK" -ne 1 ]; then
  echo "ERROR: validation archive was not safely downloaded" >&2
  exit 1
fi
exit "$REMOTE_RC"
