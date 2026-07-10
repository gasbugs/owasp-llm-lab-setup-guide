#!/bin/bash
# tests/e2e/lib/common.sh
# 본 강의 vuln-rag · vuln-agent 대상 페이로드 시도 헬퍼.
#
# 환경변수:
#   TARGET_URL       대상 base URL (예: http://localhost:8000, 8010, 8011, 8012, 8013)
#   AGENT_URL        vuln-agent base URL (예: http://localhost:8001)
#   TRIALS           각 페이로드 반복 횟수 (기본 5)
#   RESULTS_DIR      결과 저장 경로 (기본 tests/e2e/results/<ts>)
#   STRICT_ACCEPTANCE=true  확률적 지표도 강의 승인 기준으로 강제
#
# 사용:
#   source $(dirname "$0")/../lib/common.sh
#   run_payload "PI-EMERGENCY" "p1.txt" "LLM_CTF" 5
set -euo pipefail

: "${TARGET_URL:=http://localhost:8000}"
: "${AGENT_URL:=http://localhost:8001}"
: "${TRIALS:=5}"
: "${RESULTS_DIR:=tests/e2e/results/$(date +%Y%m%d-%H%M%S)}"
: "${STRICT_ACCEPTANCE:=false}"
URL_GUARD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/require_loopback_url.py"

strict_acceptance_enabled() {
  case "$STRICT_ACCEPTANCE" in
    true|TRUE|True) return 0 ;;
    *) return 1 ;;
  esac
}

require_loopback_url() {
  python3 "$URL_GUARD" "$1" || exit 2
}

require_loopback_url "$TARGET_URL"
require_loopback_url "$AGENT_URL"

mkdir -p "$RESULTS_DIR"

# === HTTP 호출 ===
chat() {
  local message="$1"
  local user_id="${2:-e2e-tester}"
  local tenant="${3:-default}"

  curl -fsS --max-time 60 \
    -X POST "$TARGET_URL/api/chat" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg m "$message" --arg u "$user_id" --arg t "$tenant" \
          '{message: $m, user_id: $u, tenant: $t}')" \
    | jq -r '.reply // .error // "ERR_NO_REPLY"'
}

chat_agent() {
  local message="$1"
  local user_id="${2:-farmer1}"

  curl -fsS --max-time 90 \
    -X POST "$AGENT_URL/api/chat" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg m "$message" --arg u "$user_id" \
          '{message: $m, user_id: $u}')"
}

inject_doc() {
  local title="$1"
  local text="$2"
  local tenant="${3:-default}"

  local response
  response=$(curl -fsS --max-time 10 -X POST "$TARGET_URL/api/admin/inject-doc" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg t "$title" --arg c "$text" --arg n "$tenant" \
          '{title: $t, text: $c, tenant: $n}')")
  printf '%s' "$response" | jq -e '.ok == true' >/dev/null
}

delete_docs_by_title() {
  local title="$1"
  local scenario="${2:-}"
  local query=""
  local docs indexes index
  if [ -n "$scenario" ]; then
    query="?scenario=$scenario"
  fi
  docs=$(curl -fsS --max-time 10 \
    "$TARGET_URL/api/admin/docs$query")
  indexes=$(printf '%s' "$docs" | jq -r --arg title "[$title]" '
    [.docs[] | select(.text | startswith($title)) | .index] | sort | reverse[]
  ')
  for index in $indexes; do
    curl -fsS --max-time 10 -X DELETE \
      "$TARGET_URL/api/admin/docs/$index$query" \
      | jq -e '.ok == true' >/dev/null
  done
}

# === 응답 판정 ===
# judge <response> <pattern>
#   pattern은 grep -E 정규식. 매칭되면 PASS, 안 되면 FAIL.
judge() {
  local response="$1"
  local pattern="$2"
  if echo "$response" | grep -qiE "$pattern" 2>/dev/null; then
    echo "PASS"
  else
    echo "FAIL"
  fi
}

# === N회 페이로드 시도 ===
# run_payload <test-id> <payload-file> <expected-pattern> [trials]
#   응답 raw를 raw/<test-id>-trial-N.txt 에 저장
#   성공률을 results.jsonl에 추가
run_payload() {
  local test_id="$1"
  local payload_file="$2"
  local expected_pattern="$3"
  local trials="${4:-$TRIALS}"

  local payload
  payload=$(cat "$payload_file")

  local raw_dir="$RESULTS_DIR/raw"
  mkdir -p "$raw_dir"

  local pass=0
  local fail=0
  local infra_fail=0
  for i in $(seq 1 "$trials"); do
    local response
    if response=$(chat "$payload"); then
      :
    else
      response="ERR_INFRA"
      infra_fail=$((infra_fail + 1))
    fi
    echo "$response" > "$raw_dir/${test_id}-trial-${i}.txt"

    local verdict
    if [ "$response" = "ERR_INFRA" ]; then
      verdict="INFRA"
    else
      verdict=$(judge "$response" "$expected_pattern")
    fi
    if [ "$verdict" = "PASS" ]; then
      pass=$((pass + 1))
    elif [ "$verdict" = "FAIL" ]; then
      fail=$((fail + 1))
    fi
    printf "  [%s] trial %d: %s\n" "$test_id" "$i" "$verdict"
  done

  local rate
  rate=$(awk "BEGIN { printf \"%.0f\", $pass*100/$trials }")

  jq -n --arg id "$test_id" \
        --arg payload "$payload_file" \
        --arg pattern "$expected_pattern" \
        --argjson trials "$trials" \
        --argjson pass "$pass" \
        --argjson fail "$fail" \
        --argjson infra_fail "$infra_fail" \
        --argjson rate "$rate" \
        --arg target "$TARGET_URL" \
        --arg ts "$(date -Iseconds)" \
        '{test_id: $id, payload_file: $payload, expected_pattern: $pattern,
          trials: $trials, pass: $pass, fail: $fail, infra_fail: $infra_fail,
          success_rate_pct: $rate,
          target: $target, timestamp: $ts}' \
    >> "$RESULTS_DIR/results.jsonl"

  printf "  [%s] SUMMARY: pass=%d fail=%d infra=%d trials=%d (%d%%)\n" \
    "$test_id" "$pass" "$fail" "$infra_fail" "$trials" "$rate"
  if [ "$infra_fail" -gt 0 ]; then
    echo "  [$test_id] INFRA: one or more model requests failed" >&2
    return 3
  fi
}

# === 인라인 페이로드 시도 (파일 아닌 문자열) ===
run_payload_inline() {
  local test_id="$1"
  local payload="$2"
  local expected_pattern="$3"
  local trials="${4:-$TRIALS}"

  local tmp
  local status=0
  tmp=$(mktemp)
  printf '%s' "$payload" > "$tmp"
  run_payload "$test_id" "$tmp" "$expected_pattern" "$trials" || status=$?
  rm -f "$tmp"
  return "$status"
}

# === 헬스체크 ===
require_healthy() {
  if ! curl -sf --max-time 5 "$TARGET_URL/healthz" >/dev/null; then
    echo "ERROR: $TARGET_URL 응답 없음. vuln-rag 컨테이너 상태 확인." >&2
    exit 3
  fi
}

require_agent_healthy() {
  if ! curl -sf --max-time 5 "$AGENT_URL/healthz" >/dev/null; then
    echo "ERROR: $AGENT_URL 응답 없음. vuln-agent 컨테이너 상태 확인." >&2
    exit 3
  fi
}

require_scenario() {
  local expected="$1"
  local actual
  actual=$(curl -fsS --max-time 5 "$TARGET_URL/healthz" | jq -r '.default_scenario // .scenario // "unknown"')
  if [ "$actual" != "$expected" ]; then
    echo "ERROR: 현재 TARGET_URL=$TARGET_URL 의 scenario=$actual, 필요한 scenario=$expected" >&2
    echo "  컨테이너를 재기동하지 말고 Day별 고정 포트를 사용하세요." >&2
    echo "  day1=http://localhost:8000 day2=http://localhost:8010 day3=http://localhost:8011 day4=http://localhost:8012 day5=http://localhost:8013" >&2
    exit 4
  fi
}
