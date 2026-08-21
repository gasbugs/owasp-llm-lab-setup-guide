#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
cleanup() {
  podman rm -f llm-security-nemo-hub-lock-canary >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

awk '
  /^  main:$/ { in_main=1 }
  in_main && /^    digest:/ {
    print "    digest: sha256:intentionally-wrong-for-lock-test"
    in_main=0
    next
  }
  { print }
' "$ROOT/versions.lock.yaml" > "$WORK/versions.lock.yaml"

podman run -d --replace --name llm-security-nemo-hub-lock-canary \
  --network slirp4netns:allow_host_loopback=true \
  -p 127.0.0.1:18194:8014 \
  -e APPLICATION_INTERNAL_TOKEN=control-plane-app-to-nemo \
  -e PRESIDIO_INTERNAL_TOKEN=control-plane-nemo-to-presidio \
  -e OLLAMA_URL=http://10.0.2.2:11434 \
  -v "$WORK/versions.lock.yaml:/app/versions.lock.yaml:ro,Z" \
  -v "$ROOT/policies/nemo-policy.yaml:/app/policies/nemo-policy.yaml:ro,Z" \
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

printf 'model_digest_mismatch_health=false chat_http=%s\n' "$status"
cat "$WORK/version-output.jsons"
