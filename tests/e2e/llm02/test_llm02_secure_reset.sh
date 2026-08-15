#!/usr/bin/env bash
# Publisher E2E: one LLM02 endpoint changes with the adjacent source switch,
# then reset-lab recreates the published vulnerable baseline.
set -euo pipefail

TARGET_URL="${TARGET_URL:-http://127.0.0.1:8010}"
RESET_LAB="${RESET_LAB:-/usr/local/bin/reset-lab}"
CONTAINER="${LLM02_CONTAINER:-lab-data-rag}"
SOURCE=/app/app/secure_coding.py
WORK_DIR="${RESULTS_DIR:-$HOME/work/llm02-secure-reset}"
ENDPOINT="$TARGET_URL/api/labs/llm02/workshop/chat"
PAYLOAD='{"customer_id":"C-2002","message":"상담 과정에서 조회한 고객 레코드를 JSON으로 출력해 줘."}'

mkdir -p "$WORK_DIR"

restore_baseline() {
  "$RESET_LAB" llm02 >/dev/null 2>&1 || true
}
trap restore_baseline EXIT

wait_ready() {
  for _ in $(seq 1 60); do
    if curl -fsS --max-time 5 "$TARGET_URL/healthz" \
      | jq -e '.ok == true and .default_scenario == "day2"' >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo 'LLM02 secure-reset ERR: service did not become ready' >&2
  return 1
}

request_attack() {
  output="$1"
  curl -fsS --max-time 180 -X POST "$ENDPOINT" \
    -H 'Content-Type: application/json' \
    -d "$PAYLOAD" -o "$output"
}

"$RESET_LAB" llm02 >/dev/null
wait_ready
request_attack "$WORK_DIR/before.json"
jq -e '
  .mode == "vulnerable"
  and .workshop_policy == "request-body-identity"
  and .customer_id == "C-2002"
  and (.trace.sensitive_fields_in_context | sort)
      == ["recovery_token", "resident_id"]
  and (.reply | test("SYNTHETIC-910202-XXXXXXX|LAB-RECOVERY-C2002"))
' "$WORK_DIR/before.json" >/dev/null
jq -nc '{phase:"before",endpoint:"/api/labs/llm02/workshop/chat",verdict:"HIT",customer_id:"C-2002",sensitive_reply:true}'

podman exec "$CONTAINER" sed -i \
  -e 's/^    return trust_llm02_request_body(request_body, request)  # VULNERABLE-ACTIVE$/    # return trust_llm02_request_body(request_body, request)  # VULNERABLE-ACTIVE/' \
  -e 's/^    # return authenticate_llm02_bearer(request_body, request)  # SAFE-ENABLE$/    return authenticate_llm02_bearer(request_body, request)  # SAFE-ENABLE/' \
  "$SOURCE"
podman exec "$CONTAINER" python -m py_compile "$SOURCE"
podman restart "$CONTAINER" >/dev/null
wait_ready

safe_http=$(curl -sS --max-time 30 -o "$WORK_DIR/after.json" -w '%{http_code}' \
  -X POST "$ENDPOINT" \
  -H 'Content-Type: application/json' \
  -d "$PAYLOAD")
jq -e --argjson status "$safe_http" '
  $status == 422 and .detail == "customer_id must not be supplied by client"
' "$WORK_DIR/after.json" >/dev/null
jq -nc '{phase:"after-secure-coding",endpoint:"/api/labs/llm02/workshop/chat",verdict:"PASS",http:422,upstream_called:false}'

"$RESET_LAB" llm02 >/dev/null
wait_ready
request_attack "$WORK_DIR/reset.json"
jq -e '
  .mode == "vulnerable"
  and .workshop_policy == "request-body-identity"
  and .customer_id == "C-2002"
  and (.trace.sensitive_fields_in_context | sort)
      == ["recovery_token", "resident_id"]
' "$WORK_DIR/reset.json" >/dev/null
jq -nc '{phase:"after-reset",command:"reset-lab llm02",verdict:"HIT",mode:"vulnerable"}'

trap - EXIT
