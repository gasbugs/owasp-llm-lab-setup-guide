#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
cleanup() {
  docker rm -f llm-security-nemo-hub-lock-canary >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

docker rm -f llm-security-nemo-hub-lock-canary >/dev/null 2>&1 || true

docker run -d --name llm-security-nemo-hub-lock-canary \
  --network llm-security-control-plane \
  -p 127.0.0.1:18194:8014 \
  -e APPLICATION_INTERNAL_TOKEN=control-plane-app-to-nemo \
  -e PRESIDIO_INTERNAL_TOKEN=control-plane-nemo-to-presidio \
  -e BEDROCK_GATEWAY_TOKEN=model-lock-canary-not-used \
  -e MODEL_GATEWAY_URL=http://llm-security-bedrock-gateway:8080 \
  -e BEDROCK_MODEL_ID=us.amazon.nova-micro-v1:0 \
  -v "$ROOT/policies/control-plane-policy.yaml:/app/policies/control-plane-policy.yaml:ro" \
  -v "$ROOT/nemo-policy-hub/config:/app/nemo-config:ro" \
  localhost/llm-security-nemo-policy-hub:1.0.0 >/dev/null

for _ in $(seq 1 60); do
  curl -sS --max-time 3 http://127.0.0.1:18194/healthz \
    | jq -e '.model_lock_valid == false' >/dev/null 2>&1 && break
  sleep 2
done

curl -sS http://127.0.0.1:18194/healthz \
  | jq -e '.ok == false and .model_lock_valid == false' >/dev/null
status="$(curl -sS --max-time 30 -o /dev/null -w '%{http_code}' \
  -X POST http://127.0.0.1:18194/api/chat \
  -H 'Authorization: Bearer control-plane-app-to-nemo' \
  -H 'Content-Type: application/json' \
  -d '{"message":"status","request_id":"digest-lock-canary","principal":{"subject":"reader","roles":["public_reader"]}}')"
test "$status" = 503

bash "$ROOT/deploy/promote-and-rollback.sh" > "$WORK/version-output.jsons"
grep -q '"candidate_version": "1.1.0-candidate"' "$WORK/version-output.jsons"
grep -q '"rollback_version": "1.0.0"' "$WORK/version-output.jsons"

printf 'model_id_mismatch_health=false chat_http=%s\n' "$status"
cat "$WORK/version-output.jsons"
