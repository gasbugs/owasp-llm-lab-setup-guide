#!/bin/bash
# Upload the student Capstone starter from the local student package to EC2.
#
# Usage:
#   AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT=yourname \
#     bash infrastructure/scripts/student/upload-capstone.sh
#
# Existing destinations fail closed. To keep a timestamped backup and install
# a fresh starter explicitly set CAPSTONE_UPLOAD_MODE=backup-replace.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${AWS_PROFILE:=owasp-llm}"
: "${AWS_REGION:?AWS_REGION is required, e.g. us-east-1}"
: "${STUDENT:?STUDENT is required, e.g. alice}"
: "${TF_DIR:=infrastructure/terraform}"
: "${DEST_DIR:=/home/ubuntu/work/my-capstone}"
: "${CAPSTONE_UPLOAD_MODE:=create}"

case "$CAPSTONE_UPLOAD_MODE" in
  create|backup-replace) ;;
  *)
    echo "ERROR: CAPSTONE_UPLOAD_MODE must be create or backup-replace." >&2
    exit 2
    ;;
esac
if [[ ! "$DEST_DIR" =~ ^/home/ubuntu/work/[A-Za-z0-9._-]+$ ]]; then
  echo "ERROR: DEST_DIR must be one direct child of /home/ubuntu/work." >&2
  exit 2
fi

if [ ! -d "capstone/app" ] || [ ! -d "capstone/attacks" ]; then
  echo "ERROR: run this script from the student package root that contains capstone/." >&2
  exit 1
fi

CAPSTONE_INSTALLER="$SCRIPT_DIR/install-capstone-archive.sh"
if [ ! -f "$CAPSTONE_INSTALLER" ]; then
  echo "ERROR: Capstone remote installer is missing: $CAPSTONE_INSTALLER" >&2
  exit 1
fi

for cmd in aws terraform jq ssh scp ssh-keygen tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    echo "Install the missing tool, then rerun this script from the student package root." >&2
    exit 1
  fi
done

INSTANCE_ID=$(terraform -chdir="$TF_DIR" output -json instance_ids | jq -r --arg student "$STUDENT" '.[$student] // empty')
if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" = "null" ]; then
  echo "ERROR: cannot find instance id for STUDENT=$STUDENT from $TF_DIR output." >&2
  exit 1
fi

STATE=$(aws ec2 describe-instances \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].State.Name' \
  --output text)
if [ "$STATE" != "running" ]; then
  echo "ERROR: instance $INSTANCE_ID is $STATE, not running." >&2
  echo "Run start-lab first:" >&2
  echo "  AWS_PROFILE=$AWS_PROFILE AWS_REGION=$AWS_REGION STUDENT=$STUDENT bash infrastructure/scripts/student/start-lab.sh" >&2
  exit 1
fi

PING=$(aws ssm describe-instance-information \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
  --query 'InstanceInformationList[0].PingStatus' \
  --output text 2>/dev/null || true)
if [ "$PING" != "Online" ]; then
  echo "ERROR: SSM agent for $INSTANCE_ID is not Online yet (current: ${PING:-unknown})." >&2
  echo "Wait 1-2 minutes after start-lab, then rerun upload-capstone.sh." >&2
  exit 1
fi

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/capstone-upload.XXXXXX")
REMOTE_KEY_INSTALLED=0
cleanup() {
  set +e
  if [ "${REMOTE_KEY_INSTALLED:-0}" = "1" ] && [ -n "${PUBKEY:-}" ]; then
    echo "[cleanup] Removing temporary SSH key from $INSTANCE_ID"
    CLEANUP_COMMAND_ID=$(aws ssm send-command \
      --profile "$AWS_PROFILE" \
      --region "$AWS_REGION" \
      --instance-ids "$INSTANCE_ID" \
      --document-name AWS-RunShellScript \
      --parameters "commands=[\"if [ -f /home/ubuntu/.ssh/authorized_keys ]; then grep -vxF '$PUBKEY' /home/ubuntu/.ssh/authorized_keys > /home/ubuntu/.ssh/authorized_keys.tmp || true; mv /home/ubuntu/.ssh/authorized_keys.tmp /home/ubuntu/.ssh/authorized_keys; chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys; chmod 600 /home/ubuntu/.ssh/authorized_keys; fi\"]" \
      --query 'Command.CommandId' \
      --output text 2>/dev/null)
    if [ -n "$CLEANUP_COMMAND_ID" ]; then
      aws ssm wait command-executed \
        --profile "$AWS_PROFILE" \
        --region "$AWS_REGION" \
        --command-id "$CLEANUP_COMMAND_ID" \
        --instance-id "$INSTANCE_ID" 2>/dev/null
    fi
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

ARCHIVE="$WORKDIR/capstone.tgz"
KEY="$WORKDIR/ssm-upload-key"
tar -czf "$ARCHIVE" capstone
ssh-keygen -q -t ed25519 -N '' -f "$KEY"
PUBKEY=$(cat "$KEY.pub")

echo "[1/5] Authorizing temporary SSH key through SSM: $INSTANCE_ID"
COMMAND_ID=$(aws ssm send-command \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --instance-ids "$INSTANCE_ID" \
  --document-name AWS-RunShellScript \
  --parameters "commands=[\"install -d -m 700 -o ubuntu -g ubuntu /home/ubuntu/.ssh\",\"grep -qxF '$PUBKEY' /home/ubuntu/.ssh/authorized_keys 2>/dev/null || echo '$PUBKEY' >> /home/ubuntu/.ssh/authorized_keys\",\"chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys\",\"chmod 600 /home/ubuntu/.ssh/authorized_keys\"]" \
  --query 'Command.CommandId' \
  --output text)
aws ssm wait command-executed \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --command-id "$COMMAND_ID" \
  --instance-id "$INSTANCE_ID"
REMOTE_KEY_INSTALLED=1

SSM_SSH="aws ssm start-session --profile $AWS_PROFILE --region $AWS_REGION --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p"

echo "[2/5] Uploading Capstone archive"
scp -i "$KEY" \
  -o StrictHostKeyChecking=no \
  -o ProxyCommand="$SSM_SSH" \
  "$ARCHIVE" \
  "ubuntu@$INSTANCE_ID:/tmp/capstone-upload.tgz"

echo "[3/5] Uploading fail-closed installer"
scp -i "$KEY" \
  -o StrictHostKeyChecking=no \
  -o ProxyCommand="$SSM_SSH" \
  "$CAPSTONE_INSTALLER" \
  "ubuntu@$INSTANCE_ID:/tmp/install-capstone-archive.sh"

printf -v REMOTE_INSTALL_COMMAND \
  'bash %q %q %q %q' \
  /tmp/install-capstone-archive.sh \
  /tmp/capstone-upload.tgz \
  "$DEST_DIR" \
  "$CAPSTONE_UPLOAD_MODE"

echo "[4/5] Installing to $DEST_DIR (mode=$CAPSTONE_UPLOAD_MODE)"
ssh -i "$KEY" \
  -o StrictHostKeyChecking=no \
  -o ProxyCommand="$SSM_SSH" \
  "ubuntu@$INSTANCE_ID" \
  "$REMOTE_INSTALL_COMMAND"

echo "[5/5] Verifying files"
ssh -i "$KEY" \
  -o StrictHostKeyChecking=no \
  -o ProxyCommand="$SSM_SSH" \
  "ubuntu@$INSTANCE_ID" \
  "test -f '$DEST_DIR/app/main.py' && test -x '$DEST_DIR/attacks/run-all.sh' && ls -1 '$DEST_DIR' | sed 's/^/  /'"

echo
echo "Capstone starter uploaded: $DEST_DIR"
if [ "$CAPSTONE_UPLOAD_MODE" = backup-replace ]; then
  echo "The previous destination was retained under ~/work/capstone-backups."
fi
echo "Next: connect with SSM and run:"
echo "  cd ~/work/my-capstone"
