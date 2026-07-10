#!/bin/bash
# LLMGoat용 헬퍼.
# vuln-rag와 endpoint/스키마가 달라 common.sh와 별도.
#   - POST /api/<challenge_id>
#   - request body: {"input": "..."}
#   - response: {"response": "...", "solved": true|false, "prompt": "..."}
#
# 환경변수:
#   GOAT_URL         LLMGoat base URL (기본 http://localhost:5000)
#   TRIALS           반복 (기본 3 — gemma-2-9b 추론 느림)
#   RESULTS_DIR      결과 디렉터리
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${GOAT_URL:=http://localhost:5000}"
: "${TRIALS:=3}"
: "${RESULTS_DIR:=tests/e2e/results/$(date +%Y%m%d-%H%M%S)-llmgoat}"

python3 "$SCRIPT_DIR/../lib/require_loopback_url.py" "$GOAT_URL" || exit 2

mkdir -p "$RESULTS_DIR"

goat_chat() {
  local challenge_id="$1"
  local input="$2"
  curl -fsS --max-time 180 \
    -X POST "$GOAT_URL/api/${challenge_id}" \
    -H 'Content-Type: application/json' \
    -b /tmp/goat-cookies.txt -c /tmp/goat-cookies.txt \
    -d "$(jq -n --arg i "$input" '{input: $i}')"
}

require_goat_healthy() {
  if ! curl -sf --max-time 5 "$GOAT_URL/api/model_status" >/dev/null 2>&1; then
    echo "ERROR: $GOAT_URL 응답 없음. lab-llmgoat 컨테이너 상태 확인." >&2
    exit 3
  fi
}

# run_goat_payload <test-id> <challenge_id> <input>
#   응답을 raw/<test-id>-trial-N.json 에 저장.
#   solved 판정은 LLMGoat 응답의 "solved" 필드 그대로 사용.
run_goat_payload() {
  local test_id="$1"
  local challenge_id="$2"
  local input="$3"
  local trials="${4:-$TRIALS}"

  local raw_dir="$RESULTS_DIR/raw"
  mkdir -p "$raw_dir"

  local pass=0
  local fail=0
  local infra_fail=0
  for i in $(seq 1 "$trials"); do
    local resp
    if resp=$(goat_chat "$challenge_id" "$input"); then
      :
    else
      resp='{"error":"infra_failure"}'
      infra_fail=$((infra_fail + 1))
    fi
    echo "$resp" > "$raw_dir/${test_id}-trial-${i}.json"

    local solved
    solved=$(echo "$resp" | jq -r '.solved // false' 2>/dev/null || echo "false")
    if [ "$infra_fail" -gt 0 ] && [ "$resp" = '{"error":"infra_failure"}' ]; then
      printf "  [%s] trial %d: INFRA\n" "$test_id" "$i"
    elif [ "$solved" = "true" ]; then
      pass=$((pass + 1))
      printf "  [%s] trial %d: PASS\n" "$test_id" "$i"
    else
      fail=$((fail + 1))
      printf "  [%s] trial %d: FAIL\n" "$test_id" "$i"
    fi
  done

  local rate
  rate=$(awk "BEGIN { printf \"%.0f\", $pass*100/$trials }")

  jq -n --arg id "$test_id" \
        --arg challenge "$challenge_id" \
        --arg input "$input" \
        --argjson trials "$trials" \
        --argjson pass "$pass" \
        --argjson fail "$fail" \
        --argjson infra_fail "$infra_fail" \
        --argjson rate "$rate" \
        --arg target "$GOAT_URL" \
        --arg ts "$(date -Iseconds)" \
        '{test_id: $id, challenge: $challenge, input: $input,
          trials: $trials, solved: $pass, fail: $fail, infra_fail: $infra_fail,
          success_rate_pct: $rate,
          target: $target, timestamp: $ts}' \
    >> "$RESULTS_DIR/results.jsonl"

  printf "  [%s] SUMMARY: pass=%d fail=%d infra=%d trials=%d (%d%%)\n" \
    "$test_id" "$pass" "$fail" "$infra_fail" "$trials" "$rate"
  if [ "$infra_fail" -gt 0 ]; then
    return 3
  fi
}
