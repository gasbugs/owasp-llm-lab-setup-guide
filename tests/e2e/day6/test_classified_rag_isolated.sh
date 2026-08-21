#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="${WORK:-/tmp/day7-classified-rag-isolated}"
PRESIDIO_IMAGE=localhost/codex-classified-presidio:latest
NEMO_IMAGE=localhost/codex-classified-nemo:latest
UI_IMAGE=localhost/codex-classified-ui:latest
INTERNAL_TOKEN=day7-classified-rag-internal

cleanup() {
  podman rm -f codex-classified-ui codex-classified-nemo \
    codex-classified-presidio >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
mkdir -p "$WORK"

curl -fsS --max-time 10 http://127.0.0.1:11434/api/tags >/dev/null

podman build -t "$PRESIDIO_IMAGE" "$ROOT/examples/day6/presidio"
podman build -t "$NEMO_IMAGE" "$ROOT/examples/day6/nemo-guardrails"
podman build -t "$UI_IMAGE" "$ROOT/docker/vuln-rag"

podman run -d --replace --name codex-classified-presidio \
  --network slirp4netns:allow_host_loopback=true \
  -p 127.0.0.1:28091:8013 \
  -e RUN_MODE=server -e GUARD_MODE=enforce -e ENABLE_LAB_ENDPOINTS=true \
  "$PRESIDIO_IMAGE" >/dev/null

podman run -d --replace --name codex-classified-nemo \
  --network slirp4netns:allow_host_loopback=true \
  -p 127.0.0.1:28092:8013 \
  -e RUN_MODE=server -e GUARD_MODE=enforce -e ENABLE_LAB_ENDPOINTS=true \
  -e OLLAMA_URL=http://10.0.2.2:11434 \
  -e PRESIDIO_URL=http://10.0.2.2:28091 \
  -e CLASSIFIED_RAG_INTERNAL_TOKEN="$INTERNAL_TOKEN" \
  "$NEMO_IMAGE" >/dev/null

podman run -d --replace --name codex-classified-ui \
  --network slirp4netns:allow_host_loopback=true \
  -p 127.0.0.1:28090:8000 \
  -e PORT=8000 -e DEFAULT_SCENARIO=day1 -e GUARD_ENGINE=presidio \
  -e PRESIDIO_URL=http://10.0.2.2:28091 \
  -e NEMO_GUARD_URL=http://10.0.2.2:28092 \
  -e CLASSIFIED_RAG_INTERNAL_TOKEN="$INTERNAL_TOKEN" \
  "$UI_IMAGE" >/dev/null

for url in \
  http://127.0.0.1:28091/healthz \
  http://127.0.0.1:28092/healthz \
  http://127.0.0.1:28090/healthz; do
  for _ in $(seq 1 90); do
    curl -fsS --max-time 2 "$url" >/dev/null 2>&1 && break
    sleep 2
  done
  curl -fsS --max-time 2 "$url" >/dev/null
done

curl -fsS --max-time 240 -X POST \
  http://127.0.0.1:28090/api/labs/guardrails/classified-rag \
  -H 'Authorization: Bearer rag-public-reader-token' \
  -H 'Content-Type: application/json' \
  -d '{"query":"공개 보안 연락처","classification":"public"}' \
  | tee "$WORK/public.json" \
  | jq '{authenticated_subject,selected_rag,application_decision,pii_detected,entity_types,redaction_applied,context,nemo_called,upstream_model_called}'

jq -e '.selected_rag=="public-rag" and .pii_detected==true and .entity_types==["EMAIL_ADDRESS"] and .redaction_applied==false and .application_decision=="allow_unredacted" and .context=="Public security contact: security@example.com." and .nemo_called==true and .upstream_model_called==false' \
  "$WORK/public.json" >/dev/null

status="$(curl -sS --max-time 30 -o "$WORK/denied.json" -w '%{http_code}' -X POST \
  http://127.0.0.1:28090/api/labs/guardrails/classified-rag \
  -H 'Authorization: Bearer rag-public-reader-token' \
  -H 'Content-Type: application/json' \
  -d '{"query":"고객 복구 연락처","classification":"restricted"}')"
test "$status" = 403
jq '{authenticated_subject,requested_classification,application_decision,blocking_reason,nemo_called}' \
  "$WORK/denied.json"
jq -e '.application_decision=="block" and .blocking_reason=="classification-not-authorized" and .nemo_called==false' \
  "$WORK/denied.json" >/dev/null

curl -fsS --max-time 240 -X POST \
  http://127.0.0.1:28090/api/labs/guardrails/classified-rag \
  -H 'Authorization: Bearer rag-support-agent-token' \
  -H 'Content-Type: application/json' \
  -d '{"query":"고객 복구 연락처","classification":"restricted"}' \
  | tee "$WORK/restricted.json" \
  | jq '{authenticated_subject,selected_rag,application_decision,pii_detected,entity_types,redaction_applied,context,nemo_called,upstream_model_called}'

jq -e '.selected_rag=="restricted-rag" and .authenticated_subject=="support-agent" and .pii_detected==true and .redaction_applied==false and .application_decision=="allow_unredacted" and .context=="Synthetic customer recovery contact: customer.demo@example.com." and .nemo_called==true' \
  "$WORK/restricted.json" >/dev/null

! podman logs codex-classified-ui 2>&1 | grep -F 'customer.demo@example.com'
! podman logs codex-classified-nemo 2>&1 | grep -F 'customer.demo@example.com'
printf 'CLASSIFIED_RAG_ISOLATED=PASS\n'
