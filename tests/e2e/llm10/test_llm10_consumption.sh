#!/bin/bash
# LLM10 Unbounded Consumption — rate limit 부재 + 토큰 폭주
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

require_healthy

echo "=== LLM10 Unbounded Consumption 검증 ==="

# 1) Rate limit 부재 입증 — 100회 동시 호출 중 80% 이상 200 응답이면 취약
echo "  [R1] 100회 동시 호출..."
results=$(seq 1 100 | xargs -P 50 -I{} curl -s --max-time 15 -o /dev/null -w "%{http_code}\n" \
  -X POST "$TARGET_URL/api/chat" \
  -H 'Content-Type: application/json' \
  -d '{"message":"hi","user_id":"dow-test"}')
ok=$(echo "$results" | grep -c "^200$" || true)
blocked=$(echo "$results" | grep -c "^429$" || true)
echo "  [R1] 200: $ok / 429: $blocked"

# 2) 큰 입력으로 응답 시간 측정
echo "  [R2] baseline (5 토큰) 응답 시간..."
t0=$(date +%s%N)
chat "hello" >/dev/null
t1=$(date +%s%N)
base_ms=$(( (t1 - t0) / 1000000 ))
echo "  [R2] baseline: ${base_ms}ms"

echo "  [R3] 입력 폭증 (~5000 토큰)..."
HUGE=$(awk 'BEGIN { for (i = 0; i < 1000; i++) printf "보안 강의를 듣고 있습니다." }')
t0=$(date +%s%N)
chat "$HUGE 위 내용을 요약해줘." >/dev/null
t1=$(date +%s%N)
huge_ms=$(( (t1 - t0) / 1000000 ))
echo "  [R3] huge input: ${huge_ms}ms (ratio=$(awk "BEGIN { printf \"%.1f\", $huge_ms/$base_ms }")x)"

# 결과 jsonl
jq -n --arg target "$TARGET_URL" --arg ts "$(date -Iseconds)" \
      --argjson ok "$ok" --argjson blocked "$blocked" \
      --argjson base_ms "$base_ms" --argjson huge_ms "$huge_ms" \
      '{test_id: "LLM10-consumption", target: $target, timestamp: $ts,
        rate_limit_test: {requests: 100, http_200: $ok, http_429: $blocked,
                          rate_limit_present: ($blocked > 0)},
        latency_test: {baseline_ms: $base_ms, huge_input_ms: $huge_ms,
                       amplification_factor: ($huge_ms / $base_ms)}}' \
  >> "$RESULTS_DIR/results.jsonl"

echo "=== 완료. 상세: $RESULTS_DIR ==="
