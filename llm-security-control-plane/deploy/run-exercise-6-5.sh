#!/usr/bin/env bash
set -euo pipefail

# Chapter 08 exercise 6.5 verifier. The learner edits the policy; this script
# builds the runtime from source and checks the submitted policy without AWS.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
  echo "usage: $0 --build-only | --policy-file PATH [--evidence-dir PATH]" >&2
}
MODE=""
POLICY_FILE=""
EVIDENCE_DIR=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --build-only) MODE=build; shift ;;
    --policy-file) [ "$#" -ge 2 ] || { usage; exit 2; }; MODE=verify; POLICY_FILE=$2; shift 2 ;;
    --evidence-dir) [ "$#" -ge 2 ] || { usage; exit 2; }; EVIDENCE_DIR=$2; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[ -n "$MODE" ] || { usage; exit 2; }
[ "$MODE" = verify ] || [ -z "$EVIDENCE_DIR" ] || { usage; exit 2; }

pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
for command in podman curl jq ss realpath; do
  command -v "$command" >/dev/null 2>&1 || fail "required command missing: $command"
done
podman info >/dev/null 2>&1 || fail "Podman is not ready for the current user"

printf '[BUILD] four control-plane images from the current checkout\n'
bash "$ROOT/deploy/build-images.sh"
for image in bedrock-gateway presidio-privacy-spoke nemo-policy-hub application-gateway; do
  podman image exists "localhost/llm-security-${image}:1.0.0" \
    || fail "image was not built: $image"
done
pass "control-plane images built from source"
[ "$MODE" = build ] && { echo 'serial-guardrail-review=BUILD_READY'; exit 0; }

POLICY_FILE="$(realpath "$POLICY_FILE")"
test -r "$POLICY_FILE" || fail "policy file is not readable: $POLICY_FILE"

NETWORK=serial-guardrail-review
BEDROCK=serial-guardrail-review-bedrock
SPOKE=serial-guardrail-review-spoke
HUB=serial-guardrail-review-hub
BEDROCK_PORT=28096
SPOKE_PORT=28093
HUB_PORT=28094
BEDROCK_TOKEN=serial-review-bedrock-token
PRESIDIO_TOKEN=serial-review-presidio-token
APPLICATION_TOKEN=serial-review-application-token
WORK="$(mktemp -d)"

cleanup() {
  podman rm -f "$HUB" "$SPOKE" "$BEDROCK" >/dev/null 2>&1 || true
  podman network rm "$NETWORK" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

for target in "$BEDROCK" "$SPOKE" "$HUB"; do
  podman container exists "$target" && fail "exercise container exists: $target"
done
podman network exists "$NETWORK" && fail "exercise network exists: $NETWORK"
for port in "$BEDROCK_PORT" "$SPOKE_PORT" "$HUB_PORT"; do
  if ss -ltn | awk -v suffix=":$port" '$4 ~ suffix "$" {found=1} END {exit(found ? 0 : 1)}'; then
    fail "exercise port is in use: $port"
  fi
done

wait_json() {
  local url=$1 expression=$2
  for _ in $(seq 1 90); do
    curl -fsS --max-time 3 "$url" 2>/dev/null \
      | jq -e "$expression" >/dev/null 2>&1 && return 0
    sleep 2
  done
  fail "service did not become ready: $url"
}

podman network create "$NETWORK" >/dev/null
podman run -d --name "$BEDROCK" --network "$NETWORK" \
  -p "127.0.0.1:${BEDROCK_PORT}:8080" \
  -e "BEDROCK_GATEWAY_TOKEN=$BEDROCK_TOKEN" \
  -v "$ROOT/tests/fake_bedrock_gateway.py:/app/server.py:ro,Z" \
  docker.io/library/python:3.12-slim python /app/server.py >/dev/null
wait_json "http://127.0.0.1:${BEDROCK_PORT}/healthz" '.ok == true'

podman run -d --name "$SPOKE" --network "$NETWORK" \
  -p "127.0.0.1:${SPOKE_PORT}:8013" \
  -e "PRESIDIO_INTERNAL_TOKEN=$PRESIDIO_TOKEN" \
  localhost/llm-security-presidio-privacy-spoke:1.0.0 >/dev/null
wait_json "http://127.0.0.1:${SPOKE_PORT}/healthz" '.ok == true'

podman run -d --name "$HUB" --network "$NETWORK" \
  -p "127.0.0.1:${HUB_PORT}:8014" \
  -e "PRESIDIO_INTERNAL_TOKEN=$PRESIDIO_TOKEN" \
  -e "APPLICATION_INTERNAL_TOKEN=$APPLICATION_TOKEN" \
  -e "BEDROCK_GATEWAY_TOKEN=$BEDROCK_TOKEN" \
  -e "PRESIDIO_URL=http://${SPOKE}:8013" \
  -e "MODEL_GATEWAY_URL=http://${BEDROCK}:8080" \
  -e BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0 \
  -e GUARD_MODE=enforce -e ASSURANCE_PROFILE=high-assurance \
  -v "$POLICY_FILE:/app/policies/control-plane-policy.yaml:ro,Z" \
  localhost/llm-security-nemo-policy-hub:1.0.0 >/dev/null
wait_json "http://127.0.0.1:${HUB_PORT}/healthz" '.ok == true'

request() {
  local request_id=$1 message=$2 output=$3
  curl -fsS --max-time 120 -X POST "http://127.0.0.1:${HUB_PORT}/api/chat" \
    -H "Authorization: Bearer $APPLICATION_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg request_id "$request_id" --arg message "$message" \
      '{request_id:$request_id,message:$message,principal:{subject:"tutorial-user",roles:["tutorial"]}}')" \
    > "$output"
}
request serial-policy-normal-01 '2 더하기 2의 결과를 숫자로 알려 주세요.' "$WORK/normal.json"
request serial-policy-email-01 'Send the incident report to analyst@example.com after review.' "$WORK/email.json"

jq -e '.guardrail.decision == "allow"
  and .guardrail.blocking_reason == null
  and .guardrail.upstream_called == true
  and (.guardrail.stage_order | index("bedrock_main")) != null
  and .guardrail.stages[0].entity_types == []' "$WORK/normal.json" >/dev/null \
  || fail "normal input contract failed"
pass "normal input reached bedrock_main"

jq -e '.guardrail.decision == "block"
  and .guardrail.blocking_reason == "input:prohibited:EMAIL_ADDRESS"
  and .guardrail.upstream_called == false
  and .guardrail.guard_model_calls == 0
  and .guardrail.stage_order == ["presidio_input"]
  and (.guardrail.stages[0].entity_types | index("EMAIL_ADDRESS")) != null' \
  "$WORK/email.json" >/dev/null \
  || fail "email input was not blocked before NeMo and Main Model"
pass "email input stopped at presidio_input before every model call"
if [ -n "$EVIDENCE_DIR" ]; then
  install -d -m 0755 "$EVIDENCE_DIR"
  install -m 0644 "$WORK/normal.json" "$EVIDENCE_DIR/normal.json"
  install -m 0644 "$WORK/email.json" "$EVIDENCE_DIR/email.json"
  printf '[EVIDENCE] %s\n' "$EVIDENCE_DIR"
fi
echo 'serial-guardrail-review=PASS'
