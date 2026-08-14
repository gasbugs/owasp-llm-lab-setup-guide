#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 \
    bash forward-lab-ports.sh i-0123456789abcdef0

Optional:
  LAB_PORTS="8080 8012"   Forward only selected ports.

The command runs on the learner laptop and keeps all SSM sessions in the
foreground. Press Ctrl+C once to close every port forward.
EOF
}

if [ "$#" -ne 1 ] || [[ "$1" != i-* ]]; then
  usage >&2
  exit 2
fi

for command in aws session-manager-plugin; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $command" >&2
    exit 1
  fi
done

INSTANCE_ID="$1"
AWS_PROFILE="${AWS_PROFILE:-owasp-llm}"
AWS_REGION="${AWS_REGION:-us-east-1}"
LAB_PORTS="${LAB_PORTS:-3000 3001 3100 3200 4318 5000 8000 8001 8002 8010 8011 8012 8013 8014 8015 8080 8099 8501 9009 9090 9093 9400 11434 12345 13133 18002 18012 18080 18090 18091 18092 18200}"
LOG_DIR="${TMPDIR:-/tmp}/owasp-llm-ssm-${INSTANCE_ID}"
PIDS=()

mkdir -p "$LOG_DIR"

cleanup() {
  trap - EXIT INT TERM
  if [ "${#PIDS[@]}" -gt 0 ]; then
    kill "${PIDS[@]}" >/dev/null 2>&1 || true
    wait "${PIDS[@]}" >/dev/null 2>&1 || true
  fi
  echo
  echo "Closed all SSM port-forwarding sessions."
}
trap cleanup EXIT INT TERM

aws sts get-caller-identity \
  --profile "$AWS_PROFILE" \
  --query Account \
  --output text >/dev/null

for port in $LAB_PORTS; do
  if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo "ERROR: invalid LAB_PORTS entry: $port" >&2
    exit 2
  fi

  if command -v lsof >/dev/null 2>&1 && \
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "ERROR: local port $port is already in use" >&2
    exit 1
  fi

  aws ssm start-session \
    --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" \
    --target "$INSTANCE_ID" \
    --document-name AWS-StartPortForwardingSession \
    --parameters "portNumber=[\"$port\"],localPortNumber=[\"$port\"]" \
    >"$LOG_DIR/$port.log" 2>&1 &
  PIDS+=("$!")
  printf 'localhost:%s -> EC2:%s (pid=%s)\n' "$port" "$port" "$!"
done

sleep 3
for pid in "${PIDS[@]}"; do
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "ERROR: an SSM session exited during startup; inspect $LOG_DIR" >&2
    exit 1
  fi
done

echo
echo "All requested forwards are running. Keep this terminal open."
echo "Logs: $LOG_DIR"
echo "Press Ctrl+C to close every session."
wait
