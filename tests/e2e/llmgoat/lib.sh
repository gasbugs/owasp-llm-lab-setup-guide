#!/bin/bash
# Shared LLMGoat live-validation helpers.
#
# Every request is restricted to an explicit loopback origin.  HTTP/transport
# failures and malformed response contracts fail closed, while `solved` remains
# a probabilistic observation.  Mutable challenge state is isolated with a
# per-challenge cookie jar and registered server-side cleanup.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${GOAT_URL:=http://localhost:5000}"
: "${TRIALS:=3}"
: "${GOAT_REQUEST_TIMEOUT:=180}"
: "${RESULTS_DIR:=tests/e2e/results/$(date +%Y%m%d-%H%M%S)-llmgoat}"

python3 "$SCRIPT_DIR/../lib/require_loopback_url.py" "$GOAT_URL" || exit 2
if [[ ! "$TRIALS" =~ ^[0-9]+$ ]] || [ "$TRIALS" -lt 1 ] || [ "$TRIALS" -gt 10 ]; then
  echo "ERROR: TRIALS must be an integer from 1 through 10" >&2
  exit 2
fi
if [[ ! "$GOAT_REQUEST_TIMEOUT" =~ ^[0-9]+$ ]] \
  || [ "$GOAT_REQUEST_TIMEOUT" -lt 10 ] \
  || [ "$GOAT_REQUEST_TIMEOUT" -gt 300 ]; then
  echo "ERROR: GOAT_REQUEST_TIMEOUT must be an integer from 10 through 300" >&2
  exit 2
fi

RAW_DIR="$RESULTS_DIR/raw"
RAW_HTTP_DIR="$RAW_DIR/http"
COOKIE_DIR="$RESULTS_DIR/.cookies"
mkdir -p "$RAW_HTTP_DIR" "$COOKIE_DIR"
chmod 0700 "$RESULTS_DIR" "$RAW_DIR" "$RAW_HTTP_DIR" "$COOKIE_DIR"
touch "$RAW_DIR/requests.jsonl" "$RAW_DIR/contract-errors.jsonl"

GOAT_CHALLENGE=""
GOAT_COOKIE_JAR=""
GOAT_SEQUENCE=0
GOAT_LAST_BODY=""
GOAT_LAST_HTTP_STATUS=""
GOAT_LAST_EVIDENCE_ID=""
GOAT_CLEANUP_LABEL=""
GOAT_CLEANUP_METHOD=""
GOAT_CLEANUP_PATH=""
GOAT_CLEANUP_PAYLOAD="null"

goat_safe_id() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-'
}

goat_begin_challenge() {
  local challenge="$1"
  if [ -n "$GOAT_CLEANUP_PATH" ]; then
    echo "ERROR: previous LLMGoat challenge cleanup is still registered" >&2
    return 2
  fi
  goat_end_challenge
  GOAT_CHALLENGE="$challenge"
  GOAT_COOKIE_JAR="$COOKIE_DIR/$(goat_safe_id "$challenge").txt"
  rm -f "$GOAT_COOKIE_JAR"
}

goat_end_challenge() {
  if [ -n "${GOAT_COOKIE_JAR:-}" ]; then
    rm -f "$GOAT_COOKIE_JAR"
  fi
  GOAT_CHALLENGE=""
  GOAT_COOKIE_JAR=""
}

goat_register_cleanup_reset() {
  GOAT_CLEANUP_LABEL="$1"
  GOAT_CLEANUP_METHOD="$2"
  GOAT_CLEANUP_PATH="$3"
  GOAT_CLEANUP_PAYLOAD="${4:-null}"
}

goat_clear_cleanup_reset() {
  GOAT_CLEANUP_LABEL=""
  GOAT_CLEANUP_METHOD=""
  GOAT_CLEANUP_PATH=""
  GOAT_CLEANUP_PAYLOAD="null"
}

goat_record_contract_error() {
  local evidence_id="$1"
  local reason="$2"
  jq -cn \
    --arg timestamp "$(date -Iseconds)" \
    --arg challenge "$GOAT_CHALLENGE" \
    --arg evidence_id "$evidence_id" \
    --arg reason "$reason" \
    --arg response_file "${GOAT_LAST_BODY#"$RESULTS_DIR/"}" \
    '{timestamp:$timestamp,challenge:$challenge,evidence_id:$evidence_id,
      reason:$reason,response_file:$response_file}' \
    >>"$RAW_DIR/contract-errors.jsonl"
}

_goat_json_request() {
  local evidence_id="$1"
  local method="$2"
  local path="$3"
  local request_json="$4"
  local mode="$5"
  local upload_file="${6:-}"
  local expected_status="${7:-200}"

  if ! printf '%s' "$request_json" | jq -Rs 'fromjson' >/dev/null 2>&1; then
    echo "ERROR: invalid request JSON for $evidence_id" >&2
    return 2
  fi
  if [[ ! "$path" =~ ^/ ]]; then
    echo "ERROR: LLMGoat request path must begin with /" >&2
    return 2
  fi
  if [ -z "$GOAT_COOKIE_JAR" ]; then
    echo "ERROR: goat_begin_challenge must run before HTTP requests" >&2
    return 2
  fi

  GOAT_SEQUENCE=$((GOAT_SEQUENCE + 1))
  local safe_id body_file http_status curl_rc json_valid infra_ok body_sha
  safe_id=$(goat_safe_id "$GOAT_CHALLENGE-$evidence_id")
  body_file="$RAW_HTTP_DIR/$(printf '%03d' "$GOAT_SEQUENCE")-$safe_id.json"
  : >"$body_file"

  local -a curl_args=(
    curl --noproxy '*' -sS --max-time "$GOAT_REQUEST_TIMEOUT"
    -X "$method"
    -b "$GOAT_COOKIE_JAR" -c "$GOAT_COOKIE_JAR"
    -o "$body_file" -w '%{http_code}'
  )
  if [ "$mode" = "json" ] && [ "$request_json" != "null" ]; then
    curl_args+=(
      -H 'Content-Type: application/json'
      --data-binary "$request_json"
    )
  elif [ "$mode" = "multipart" ]; then
    if [ ! -f "$upload_file" ]; then
      echo "ERROR: upload file not found: $upload_file" >&2
      return 2
    fi
    curl_args+=(-F "file=@$upload_file;type=application/json")
  fi
  curl_args+=("$GOAT_URL$path")

  if http_status=$("${curl_args[@]}"); then
    curl_rc=0
  else
    curl_rc=$?
  fi

  json_valid=false
  if jq -Rs 'fromjson' "$body_file" >/dev/null 2>&1; then
    json_valid=true
  fi
  infra_ok=false
  if [ "$curl_rc" -eq 0 ] \
    && [ "$http_status" = "$expected_status" ] \
    && [ "$json_valid" = true ]; then
    infra_ok=true
  fi
  body_sha=$(sha256sum "$body_file" | awk '{print $1}')

  jq -cn \
    --arg timestamp "$(date -Iseconds)" \
    --arg challenge "$GOAT_CHALLENGE" \
    --arg evidence_id "$evidence_id" \
    --arg method "$method" \
    --arg url "$GOAT_URL$path" \
    --arg request_json "$request_json" \
    --arg response_file "${body_file#"$RESULTS_DIR/"}" \
    --arg response_sha256 "$body_sha" \
    --rawfile response_raw "$body_file" \
    --arg http_status "$http_status" \
    --argjson curl_rc "$curl_rc" \
    --argjson json_valid "$json_valid" \
    --argjson infra_ok "$infra_ok" \
    '{timestamp:$timestamp,challenge:$challenge,evidence_id:$evidence_id,
      request:{method:$method,url:$url,raw_json:$request_json,
        json:(try ($request_json|fromjson) catch null)},
      transport:{curl_rc:$curl_rc,http_status:$http_status},
      response:{raw:$response_raw,json:(try ($response_raw|fromjson) catch null),
        json_valid:$json_valid,file:$response_file,sha256:$response_sha256},
      infra_ok:$infra_ok}' \
    >>"$RAW_DIR/requests.jsonl"

  GOAT_LAST_BODY="$body_file"
  GOAT_LAST_HTTP_STATUS="$http_status"
  GOAT_LAST_EVIDENCE_ID="$evidence_id"
  if [ "$infra_ok" != true ]; then
    echo "ERROR: $evidence_id infrastructure failure (curl=$curl_rc http=${http_status:-none} json=$json_valid)" >&2
    return 3
  fi
}

goat_json_request() {
  _goat_json_request "$1" "$2" "$3" "${4:-null}" json "" "${5:-200}"
}

goat_multipart_json_request() {
  local evidence_id="$1"
  local method="$2"
  local path="$3"
  local upload_file="$4"
  local upload_sha request_json
  upload_sha=$(sha256sum "$upload_file" | awk '{print $1}')
  request_json=$(jq -cn \
    --arg file "${upload_file#"$RESULTS_DIR/"}" \
    --arg sha256 "$upload_sha" \
    '{multipart_file:$file,multipart_file_sha256:$sha256}')
  _goat_json_request "$evidence_id" "$method" "$path" "$request_json" \
    multipart "$upload_file" "${5:-200}"
}

require_goat_healthy() {
  goat_json_request "model-status" GET "/api/model_status" null
  if ! jq -e '.model_busy | type == "boolean"' "$GOAT_LAST_BODY" >/dev/null; then
    goat_record_contract_error "model-status" "model_busy boolean missing"
    return 3
  fi
  if [ "$(jq -r '.model_busy' "$GOAT_LAST_BODY")" != "false" ]; then
    goat_record_contract_error "model-status" "LLM is busy before challenge start"
    echo "ERROR: LLMGoat model is already busy" >&2
    return 3
  fi
}

run_goat_json_payload() {
  local test_id="$1"
  local challenge_id="$2"
  local payload_json="$3"
  local trials="${4:-$TRIALS}"
  local solved_count=0 unsolved_count=0 infra_fail=0 attempted=0 trial solved

  for trial in $(seq 1 "$trials"); do
    if ! goat_json_request "$test_id-trial-$trial" POST "/api/$challenge_id" "$payload_json"; then
      infra_fail=1
      break
    fi
    attempted=$((attempted + 1))
    if ! jq -e '
        type == "object"
        and (.response | type == "string" and length > 0)
        and (.solved | type == "boolean")
      ' "$GOAT_LAST_BODY" >/dev/null; then
      goat_record_contract_error "$test_id-trial-$trial" \
        "challenge response requires string response and boolean solved"
      infra_fail=1
      break
    fi
    solved=$(jq -r '.solved' "$GOAT_LAST_BODY")
    if [ "$solved" = true ]; then
      solved_count=$((solved_count + 1))
      printf '  [%s] trial %d: SOLVED (observation)\n' "$test_id" "$trial"
    else
      unsolved_count=$((unsolved_count + 1))
      printf '  [%s] trial %d: UNSOLVED (observation)\n' "$test_id" "$trial"
    fi
  done

  local rate=0 verdict=OBSERVED
  if [ "$attempted" -gt 0 ]; then
    rate=$(awk "BEGIN { printf \"%.0f\", $solved_count*100/$attempted }")
  fi
  if [ "$infra_fail" -ne 0 ] || [ "$attempted" -ne "$trials" ]; then
    verdict=INFRA_FAIL
    infra_fail=1
  fi

  jq -cn \
    --arg test_id "$test_id" \
    --arg challenge "$challenge_id" \
    --arg target "$GOAT_URL" \
    --arg timestamp "$(date -Iseconds)" \
    --arg verdict "$verdict" \
    --argjson request "$payload_json" \
    --argjson trials "$trials" \
    --argjson trials_attempted "$attempted" \
    --argjson solved "$solved_count" \
    --argjson unsolved "$unsolved_count" \
    --argjson infra_fail "$infra_fail" \
    --argjson rate "$rate" \
    '{test_id:$test_id,challenge:$challenge,request:$request,target:$target,
      timestamp:$timestamp,outcome_policy:"observation-only",verdict:$verdict,
      trials:$trials,trials_attempted:$trials_attempted,
      solved:$solved,solved_count:$solved,fail:$unsolved,
      unsolved_count:$unsolved,infra_fail:$infra_fail,
      success_rate_pct:$rate,solved_rate_pct:$rate,
      raw_evidence:"raw/requests.jsonl"}' \
    >>"$RESULTS_DIR/results.jsonl"

  printf '  [%s] SUMMARY: solved=%d unsolved=%d infra=%d attempted=%d/%d (%d%%)\n' \
    "$test_id" "$solved_count" "$unsolved_count" "$infra_fail" \
    "$attempted" "$trials" "$rate"
  [ "$infra_fail" -eq 0 ] || return 3
}

run_goat_payload() {
  local payload_json
  payload_json=$(jq -cn --arg input "$3" '{input:$input}')
  run_goat_json_payload "$1" "$2" "$payload_json" "${4:-$TRIALS}"
}

goat_cleanup() {
  local original_rc=$?
  trap - EXIT
  trap '' HUP INT TERM
  set +e
  local cleanup_rc=0
  if [ -n "$GOAT_CLEANUP_PATH" ] && [ -n "$GOAT_COOKIE_JAR" ]; then
    if goat_json_request "$GOAT_CLEANUP_LABEL" "$GOAT_CLEANUP_METHOD" \
      "$GOAT_CLEANUP_PATH" "$GOAT_CLEANUP_PAYLOAD"; then
      cleanup_rc=0
    else
      cleanup_rc=$?
    fi
    if [ "$cleanup_rc" -eq 0 ]; then
      case "$GOAT_CLEANUP_PATH" in
        */reset_reviews)
          jq -e '.success == true' "$GOAT_LAST_BODY" >/dev/null \
            || cleanup_rc=3
          ;;
        */reset_vectors)
          jq -e '.status == "Vectors reset to default"' \
            "$GOAT_LAST_BODY" >/dev/null || cleanup_rc=3
          ;;
      esac
      if [ "$cleanup_rc" -ne 0 ]; then
        goat_record_contract_error "$GOAT_CLEANUP_LABEL" \
          "registered cleanup response contract failed"
      fi
    fi
  fi
  goat_end_challenge
  rm -rf "$COOKIE_DIR"
  if [ "$original_rc" -eq 0 ] && [ "$cleanup_rc" -ne 0 ]; then
    original_rc=3
  fi
  exit "$original_rc"
}

goat_exit_on_signal() {
  local signal_rc="$1"
  trap - HUP INT TERM
  exit "$signal_rc"
}

trap goat_cleanup EXIT
trap 'goat_exit_on_signal 129' HUP
trap 'goat_exit_on_signal 130' INT
trap 'goat_exit_on_signal 143' TERM
