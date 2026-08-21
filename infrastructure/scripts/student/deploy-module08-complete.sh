#!/usr/bin/env bash
set -euo pipefail

# Rebuild only the learner-created Module 07 and Module 08 environments.
# Bootstrap-owned lab-ollama, models, common lab containers and host tooling
# are deliberately outside every cleanup command in this script.

REPO_ROOT=${SETUP_REPO:-$HOME/owasp-llm-lab-setup-guide}
MONITOR_DIR=$REPO_ROOT/examples/security-monitoring
PREPARE_SCRIPT=$REPO_ROOT/infrastructure/scripts/student/prepare-module08.sh
COMPOSE=(podman compose --file "$MONITOR_DIR/compose.yaml")

if command -v nvidia-smi >/dev/null 2>&1; then
  COMPOSE+=(--file "$MONITOR_DIR/compose.gpu.yaml")
fi

pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

wait_json() {
  local url=$1 expression=$2
  for _ in $(seq 1 90); do
    curl -fsS --max-time 10 "$url" 2>/dev/null \
      | jq -e "$expression" >/dev/null 2>&1 && return 0
    sleep 2
  done
  fail "validation contract not satisfied: $url"
}

for command in podman curl jq git; do
  command -v "$command" >/dev/null 2>&1 || fail "required command missing: $command"
done
test -d "$MONITOR_DIR" || fail "setup repository not found: $REPO_ROOT"
test -x "$PREPARE_SCRIPT" || fail "prepare script is not executable: $PREPARE_SCRIPT"

podman info >/dev/null
podman container exists lab-ollama || fail "bootstrap-owned lab-ollama is not running"
curl -fsS --max-time 10 http://127.0.0.1:11434/api/tags >/dev/null \
  || fail "bootstrap-owned Ollama API is unavailable"
pass "bootstrap-owned Ollama and models preserved"

cd "$MONITOR_DIR"

# This Compose command is scoped by the project name in compose.yaml. It does
# not select bootstrap containers or volumes from the common course stack.
"${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true

for name in day6-guardrail-ui day6-presidio-api day6-nemo-guardrails-api; do
  podman rm -f "$name" >/dev/null 2>&1 || true
done

# Remove the retired Mimir volume even when it is no longer present in the new
# Compose definition. Exact names prevent unrelated learner data deletion.
for volume in \
  llm-security-observability_mimir-data \
  security-monitoring_mimir-data; do
  podman volume rm "$volume" >/dev/null 2>&1 || true
done
pass "previous Module 07 and Module 08 runtime removed"

# Build the project-owned Module 08 image from this checkout, pull only pinned
# upstream product images, and deploy the complete observability stack.
"${COMPOSE[@]}" up --detach --build
for _ in $(seq 1 90); do
  curl -fsS --max-time 5 http://127.0.0.1:8014/healthz >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS --max-time 5 http://127.0.0.1:8014/healthz >/dev/null \
  || fail "Module 08 gateway did not become ready"
pass "Module 08 observability stack built from current source"

# prepare-module08 --repair builds Module 07 project-owned images from this
# checkout, connects them to the stack and verifies normal, PII and injection.
SETUP_REPO="$REPO_ROOT" bash "$PREPARE_SCRIPT" --repair

normal_result=$(curl -fsS --max-time 240 -X POST http://127.0.0.1:8014/api/chat \
  -H 'Authorization: Bearer llm-monitor-acme-token' \
  -H 'Content-Type: application/json' \
  -d '{"request_id":"module08-complete-normal","message":"공개된 사고 대응 절차를 한 문장으로 알려 주세요."}')
jq -e '.application_decision == "allow" and .upstream_called == true and
  .blocked_stage == null and (.trace_id | length) == 32' \
  >/dev/null <<<"$normal_result" \
  || fail "normal request did not complete through the real LLM path"
trace_id=$(jq -r '.trace_id' <<<"$normal_result")

wait_json "http://127.0.0.1:3200/api/traces/$trace_id" \
  '([.batches[].scopeSpans[].spans[].name] | index("llm.security.chat") != null and index("POST /retrieve") != null and index("llm.ollama.generate") != null)'
wait_json 'http://127.0.0.1:9090/api/v1/query?query=sum(traces_spanmetrics_calls_total)' \
  '.status == "success" and (.data.result[0].value[1] | tonumber) > 0'
wait_json 'http://127.0.0.1:9090/api/v1/query?query=sum(traces_service_graph_request_total)' \
  '.status == "success" and (.data.result[0].value[1] | tonumber) > 0'
wait_json 'http://127.0.0.1:3001/api/datasources' \
  'any(.[]; .uid == "llm-security-prometheus") and any(.[]; .uid == "llm-security-loki") and any(.[]; .uid == "llm-security-tempo")'
curl -fsS --max-time 10 http://127.0.0.1:9093/-/ready >/dev/null \
  || fail "Alertmanager is unavailable"
pass "normal, PII, injection, log, trace, metric and datasource contracts verified"

pass "Module 07 and Module 08 complete runtime deployed from current source"
printf '[READY] Continue with Module 08 signal collection labs\n'
