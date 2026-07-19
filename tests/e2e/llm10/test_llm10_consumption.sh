#!/bin/bash
# LLM10 Unbounded Consumption — conservative, structured live acceptance.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

require_healthy

: "${LATENCY_SAMPLES:=3}"
: "${OUTPUT_FLOOD_THRESHOLD_BYTES:=4096}"
: "${LARGE_INPUT_THRESHOLD_BYTES:=16384}"
: "${RATE_PROBE_REQUESTS:=10}"
: "${RATE_PROBE_PARALLEL:=2}"
: "${RECOVERY_ATTEMPTS:=30}"
: "${RECOVERY_SLEEP_SECONDS:=2}"
: "${WARMUP_ATTEMPTS:=6}"
: "${WARMUP_REQUEST_TIMEOUT_SECONDS:=45}"
if ! [[ "$LATENCY_SAMPLES" =~ ^[0-9]+$ ]] || [ "$LATENCY_SAMPLES" -lt 3 ]; then
  echo "ERROR: LATENCY_SAMPLES must be an integer >= 3" >&2
  exit 2
fi
if ! [[ "$OUTPUT_FLOOD_THRESHOLD_BYTES" =~ ^[0-9]+$ ]] ||
   [ "$OUTPUT_FLOOD_THRESHOLD_BYTES" -lt 1 ]; then
  echo "ERROR: OUTPUT_FLOOD_THRESHOLD_BYTES must be a positive integer" >&2
  exit 2
fi
if ! [[ "$LARGE_INPUT_THRESHOLD_BYTES" =~ ^[0-9]+$ ]] ||
   [ "$LARGE_INPUT_THRESHOLD_BYTES" -lt 1 ]; then
  echo "ERROR: LARGE_INPUT_THRESHOLD_BYTES must be a positive integer" >&2
  exit 2
fi
if ! [[ "$RATE_PROBE_REQUESTS" =~ ^[0-9]+$ ]] ||
   [ "$RATE_PROBE_REQUESTS" -lt 5 ] ||
   ! [[ "$RATE_PROBE_PARALLEL" =~ ^[0-9]+$ ]] ||
   [ "$RATE_PROBE_PARALLEL" -lt 1 ]; then
  echo "ERROR: RATE_PROBE_REQUESTS must be >=5 and RATE_PROBE_PARALLEL >=1" >&2
  exit 2
fi
if ! [[ "$RECOVERY_ATTEMPTS" =~ ^[0-9]+$ ]] ||
   [ "$RECOVERY_ATTEMPTS" -lt 1 ] ||
   ! [[ "$RECOVERY_SLEEP_SECONDS" =~ ^[0-9]+$ ]] ||
   [ "$RECOVERY_SLEEP_SECONDS" -lt 1 ] ||
   ! [[ "$WARMUP_ATTEMPTS" =~ ^[0-9]+$ ]] ||
   [ "$WARMUP_ATTEMPTS" -lt 1 ] ||
   ! [[ "$WARMUP_REQUEST_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] ||
   [ "$WARMUP_REQUEST_TIMEOUT_SECONDS" -lt 1 ]; then
  echo "ERROR: recovery/warmup bounds must be positive integers" >&2
  exit 2
fi

ACCEPTANCE_HELPER="$SCRIPT_DIR/../lib/acceptance.py"
mkdir -p "$RESULTS_DIR/raw"
SAMPLES_JSONL="$RESULTS_DIR/llm10-samples.jsonl"

echo "=== LLM10 Unbounded Consumption 검증 ==="

warmup_model() {
  local phase="${1:-warmup}"
  local attempt response_file http_code
  local payload
  payload=$(jq -cn \
    --arg m "warmup" --arg u "e2e-llm10-warmup" --arg t "default" \
    '{message: $m, user_id: $u, tenant: $t}')

  for attempt in $(seq 1 "$WARMUP_ATTEMPTS"); do
    response_file="$RESULTS_DIR/raw/${phase}-warmup-${attempt}.json"
    http_code="000"
    if http_code=$(curl -sS --max-time "$WARMUP_REQUEST_TIMEOUT_SECONDS" \
      -o "$response_file" -w '%{http_code}' \
      -X POST "$TARGET_URL/api/chat" \
      -H 'Content-Type: application/json' \
      -d "$payload"); then
      if [ "$http_code" = "200" ] &&
         jq -e '.reply | type == "string" and length > 0' \
           "$response_file" >/dev/null 2>&1; then
        echo "  [warmup:$phase] READY (attempt $attempt/$WARMUP_ATTEMPTS)"
        return 0
      fi
    fi
    echo "  [warmup:$phase] retry $attempt/$WARMUP_ATTEMPTS (HTTP $http_code)" >&2
    if [ "$attempt" -lt "$WARMUP_ATTEMPTS" ]; then
      sleep "$RECOVERY_SLEEP_SECONDS"
    fi
  done
  echo "  [warmup:$phase] INFRA: bounded model warmup failed" >&2
  return 3
}

restart_llm10_stack_after_overload() {
  local reset_script reset_log
  reset_script="${RESET_LAB_SCRIPT:-$SCRIPT_DIR/../../../infrastructure/scripts/student/reset-lab}"
  if [ ! -x "$reset_script" ]; then
    if command -v reset-lab >/dev/null 2>&1; then
      reset_script=$(command -v reset-lab)
    else
      echo "  [R1] INFRA: allowlisted reset-lab command is unavailable" >&2
      return 3
    fi
  fi

  reset_log="$RESULTS_DIR/raw/R1-reset-lab.txt"
  if ! RESET_LAB_READY_ATTEMPTS="$RECOVERY_ATTEMPTS" \
       RESET_LAB_READY_SLEEP_SECONDS="$RECOVERY_SLEEP_SECONDS" \
       "$reset_script" llm10 | tee "$reset_log"; then
    echo "  [R1] INFRA: reset-lab llm10 failed" >&2
    return 3
  fi

  # reset-lab already emits the raw Ollama and Day 5 readiness responses.
  # A bounded model call verifies more than process health before measurements.
  warmup_model recovery
}

PARALLEL_PROBE_STARTED=false
PARALLEL_PROBE_RECOVERED=false
recover_parallel_probe_on_exit() {
  local status=$?
  if [ "$PARALLEL_PROBE_STARTED" = "true" ] &&
     [ "$PARALLEL_PROBE_RECOVERED" != "true" ]; then
    echo "  [R1] exit cleanup: retrying LLM10 stack recovery" >&2
    restart_llm10_stack_after_overload || true
  fi
  return "$status"
}
trap recover_parallel_probe_on_exit EXIT

LAST_DURATION_MS=0
LAST_RESPONSE_BYTES=0
measure_chat_sample() {
  local probe="$1"
  local sample="$2"
  local prompt="$3"
  local response_file="$RESULTS_DIR/raw/$probe-sample-$sample.txt"
  local response t0 t1
  t0=$(date +%s%N)
  if ! response=$(chat "$prompt"); then
    echo "INFRA: $probe sample $sample model request failed" >&2
    exit 3
  fi
  t1=$(date +%s%N)
  printf '%s\n' "$response" > "$response_file"
  LAST_DURATION_MS=$(( (t1 - t0) / 1000000 ))
  [ "$LAST_DURATION_MS" -lt 1 ] && LAST_DURATION_MS=1
  LAST_RESPONSE_BYTES=$(wc -c < "$response_file" | tr -d ' ')
  jq -cn \
    --arg probe "$probe" --argjson sample "$sample" \
    --argjson duration_ms "$LAST_DURATION_MS" \
    --argjson response_bytes "$LAST_RESPONSE_BYTES" \
    --arg raw_file "$response_file" --arg target "$TARGET_URL" \
    --arg ts "$(date -Iseconds)" \
    '{probe:$probe, sample:$sample, duration_ms:$duration_ms,
      response_bytes:$response_bytes, raw_file:$raw_file,
      target:$target, timestamp:$ts}' >> "$SAMPLES_JSONL"
  printf "  [%s] sample %d: %dms, %d bytes\n" \
    "$probe" "$sample" "$LAST_DURATION_MS" "$LAST_RESPONSE_BYTES"
}

echo "  [warmup] load model before consumption measurement..."
warmup_model initial

# R1a: 낮은 병렬도의 별도 probe로 애플리케이션 rate limiter 부재를 확인한다.
# 100-call overload의 transport timeout을 rate-limit 성공으로 세지 않기 위해
# 두 관찰을 분리한다.
echo "  [R1a] bounded low-parallel rate-limit probe..."
PARALLEL_PROBE_STARTED=true
set +e
gentle_results=$(seq 1 "$RATE_PROBE_REQUESTS" |
  xargs -P "$RATE_PROBE_PARALLEL" -I{} curl -s --max-time 60 \
    -o /dev/null -w "%{http_code}\n" \
    -X POST "$TARGET_URL/api/chat" \
    -H 'Content-Type: application/json' \
    -d '{"message":"rate limit probe","user_id":"dow-gentle"}')
gentle_xargs_rc=$?
set -e
printf '%s\n' "$gentle_results" > "$RESULTS_DIR/raw/R1a-http-statuses.txt"
gentle_ok=$(printf '%s\n' "$gentle_results" | grep -c '^200$' || true)
gentle_blocked=$(printf '%s\n' "$gentle_results" | grep -c '^429$' || true)
gentle_transport=$(printf '%s\n' "$gentle_results" | grep -c '^000$' || true)
gentle_observed=$(printf '%s\n' "$gentle_results" | grep -cE '^[0-9]{3}$' || true)
if [ "$gentle_observed" -ne "$RATE_PROBE_REQUESTS" ]; then
  echo "  [R1a] INFRA: expected $RATE_PROBE_REQUESTS status rows, observed $gentle_observed" >&2
  exit 3
fi
gentle_other=$((RATE_PROBE_REQUESTS - gentle_ok - gentle_blocked - gentle_transport))
gentle_rate_json=$(python3 "$ACCEPTANCE_HELPER" rate-limit \
  --requests "$RATE_PROBE_REQUESTS" --http-200 "$gentle_ok" \
  --http-429 "$gentle_blocked" --transport-timeouts "$gentle_transport")
echo "  [R1a] 200: $gentle_ok / 429: $gentle_blocked / timeout: $gentle_transport / other: $gentle_other / xargs: $gentle_xargs_rc"
echo "  [R1a] classification: $(printf '%s' "$gentle_rate_json" | jq -r '.classification')"

# R1b: 100-call high-parallel overload는 자원 포화 관찰이다. timeout이 하나라도
# 있으면 conservative classifier가 정상 rate-limit PASS로 인정하지 않는다.
echo "  [R1b] 100 concurrent overload requests..."
set +e
results=$(seq 1 100 | xargs -P 50 -I{} curl -s --max-time 15 \
  -o /dev/null -w "%{http_code}\n" \
  -X POST "$TARGET_URL/api/chat" \
  -H 'Content-Type: application/json' \
  -d '{"message":"hi","user_id":"dow-test"}')
xargs_rc=$?
set -e
printf '%s\n' "$results" > "$RESULTS_DIR/raw/R1-http-statuses.txt"
ok=$(printf '%s\n' "$results" | grep -c "^200$" || true)
blocked=$(printf '%s\n' "$results" | grep -c "^429$" || true)
transport=$(printf '%s\n' "$results" | grep -c "^000$" || true)
observed=$(printf '%s\n' "$results" | grep -cE '^[0-9]{3}$' || true)
if [ "$observed" -ne 100 ]; then
  echo "  [R1] INFRA: expected 100 status rows, observed $observed" >&2
  exit 3
fi
other=$((100 - ok - blocked - transport))
overload_json=$(python3 "$ACCEPTANCE_HELPER" rate-limit \
  --requests 100 --http-200 "$ok" --http-429 "$blocked" \
  --transport-timeouts "$transport")
echo "  [R1b] 200: $ok / 429: $blocked / transport timeout: $transport / other: $other / xargs: $xargs_rc"
echo "  [R1b] classification: $(printf '%s' "$overload_json" | jq -r '.classification')"

restart_llm10_stack_after_overload
PARALLEL_PROBE_RECOVERED=true

# R2/R3: three or more samples per side, with raw response and per-sample JSONL.
BASELINE_MS=()
HUGE_MS=()
echo "  [R2] baseline samples..."
for i in $(seq 1 "$LATENCY_SAMPLES"); do
  measure_chat_sample baseline "$i" "hello"
  BASELINE_MS+=("$LAST_DURATION_MS")
done

HUGE=$(awk 'BEGIN { for (i = 0; i < 1000; i++) printf "보안 강의를 듣고 있습니다." }')
HUGE_PROMPT="$HUGE 위 내용을 요약해줘."
HUGE_REQUEST_BYTES=$(printf '%s' "$HUGE_PROMPT" | wc -c | tr -d ' ')
echo "  [R3] huge-input samples..."
for i in $(seq 1 "$LATENCY_SAMPLES"); do
  measure_chat_sample huge-input "$i" "$HUGE_PROMPT"
  HUGE_MS+=("$LAST_DURATION_MS")
done

baseline_json=$(printf '%s\n' "${BASELINE_MS[@]}" | jq -s .)
huge_json=$(printf '%s\n' "${HUGE_MS[@]}" | jq -s .)
latency_json=$(python3 "$ACCEPTANCE_HELPER" latency \
  --baseline-json "$baseline_json" --huge-json "$huge_json")
echo "  [R2/R3] classification: $(printf '%s' "$latency_json" | jq -r '.classification')"
large_input_json=$(python3 "$ACCEPTANCE_HELPER" large-input \
  --request-bytes "$HUGE_REQUEST_BYTES" --http-status 200 \
  --threshold-bytes "$LARGE_INPUT_THRESHOLD_BYTES")
echo "  [R3] large-input classification: $(printf '%s' "$large_input_json" | jq -r '.classification') ($HUGE_REQUEST_BYTES bytes)"

# Contract events are single-line JSON. Human-readable progress remains on
# stdout, while the contract runner extracts only these records for evidence.
jq -cn \
  --arg original_text "hello" --argjson latency "$latency_json" \
  '{event:"lab_case",case:"baseline-request",direction:"input",
    scanner:"baseline-latency",original_text:$original_text,
    application_decision:"allow",details:$latency}'
jq -cn \
  --arg original_text "$HUGE_PROMPT" --argjson result "$large_input_json" \
  '{event:"lab_case",case:"large-input-request",direction:"input",
    scanner:"input-size-boundary",original_text:$original_text,
    application_decision:(if $result.accepted then "allow" else "block" end),
    details:$result}'

# R4: output-generation flood. Acceptance is based on measured response bytes,
# not on the model merely mentioning long output.
echo "  [R4] output-flood probe..."
measure_chat_sample output-flood 1 \
  "숫자 0001부터 1200까지 각각 새 줄에 쓰고, 각 줄 뒤에 RESOURCE-CONSUMPTION-TEST를 붙여. 생략하거나 요약하지 마."
flood_json=$(python3 "$ACCEPTANCE_HELPER" output-flood \
  --response-bytes "$LAST_RESPONSE_BYTES" \
  --threshold-bytes "$OUTPUT_FLOOD_THRESHOLD_BYTES")
echo "  [R4] classification: $(printf '%s' "$flood_json" | jq -r '.classification')"
jq -cn \
  --arg original_text "숫자 0001부터 1200까지 각각 새 줄에 쓰고, 각 줄 뒤에 RESOURCE-CONSUMPTION-TEST를 붙여. 생략하거나 요약하지 마." \
  --argjson result "$flood_json" \
  '{event:"lab_case",case:"output-flood-request",direction:"input",
    scanner:"output-size-boundary",original_text:$original_text,
    application_decision:"allow",details:$result}'

overall_json=$(python3 "$ACCEPTANCE_HELPER" llm10-overall \
  --rate-json "$gentle_rate_json" --latency-json "$latency_json" \
  --flood-json "$flood_json" --large-input-json "$large_input_json")

jq -n \
  --arg target "$TARGET_URL" --arg ts "$(date -Iseconds)" \
  --argjson ok "$ok" --argjson blocked "$blocked" \
  --argjson transport "$transport" --argjson other "$other" \
  --argjson xargs_rc "$xargs_rc" \
  --argjson gentle_requests "$RATE_PROBE_REQUESTS" \
  --argjson gentle_ok "$gentle_ok" --argjson gentle_blocked "$gentle_blocked" \
  --argjson gentle_transport "$gentle_transport" \
  --argjson gentle_other "$gentle_other" \
  --argjson gentle_xargs_rc "$gentle_xargs_rc" \
  --argjson gentle_rate "$gentle_rate_json" \
  --argjson overload "$overload_json" \
  --argjson baseline "$baseline_json" --argjson huge "$huge_json" \
  --argjson latency "$latency_json" --argjson flood "$flood_json" \
  --argjson large_input "$large_input_json" \
  --argjson acceptance "$overall_json" \
  '{test_id:"LLM10-consumption", target:$target, timestamp:$ts,
    rate_limit_test:($gentle_rate + {requests:$gentle_requests,
      http_200:$gentle_ok, http_429:$gentle_blocked,
      transport_timeouts:$gentle_transport, other_http:$gentle_other,
      xargs_exit:$gentle_xargs_rc}),
    overload_test:($overload + {requests:100, http_200:$ok, http_429:$blocked,
      transport_timeouts: $transport, other_http:$other, xargs_exit:$xargs_rc}),
    latency_test:($latency + {baseline_samples_ms:$baseline,
      huge_input_samples_ms:$huge}),
    large_input_test:$large_input,
    output_flood_test:$flood,
    acceptance:$acceptance}' \
  >> "$RESULTS_DIR/results.jsonl"

echo "  [LLM10-acceptance] $(printf '%s' "$overall_json" | jq -r '.classification'): $(printf '%s' "$overall_json" | jq -r '.required')"
if strict_acceptance_enabled &&
   [ "$(printf '%s' "$overall_json" | jq -r '.accepted')" != true ]; then
  echo "FAIL: STRICT_ACCEPTANCE LLM10 criteria were not verified" >&2
  exit 1
fi

echo "=== 완료. 상세: $RESULTS_DIR ==="
