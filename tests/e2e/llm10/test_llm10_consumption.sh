#!/bin/bash
# LLM10 Unbounded Consumption — rate limit 부재 + 토큰 폭주
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

require_healthy

echo "=== LLM10 Unbounded Consumption 검증 ==="

restart_ollama_after_overload() {
  local -a runtime=(podman)
  if ! podman container exists lab-ollama 2>/dev/null; then
    if command -v sudo >/dev/null 2>&1 && id ubuntu >/dev/null 2>&1; then
      runtime=(sudo -u ubuntu env XDG_RUNTIME_DIR=/run/user/1000 podman)
    else
      echo "  [R1] INFRA: lab-ollama container owner를 확인할 수 없음" >&2
      return 3
    fi
  fi
  if ! "${runtime[@]}" restart lab-ollama >/dev/null; then
    echo "  [R1] INFRA: overload 뒤 lab-ollama restart 실패" >&2
    return 3
  fi
  for _ in $(seq 1 60); do
    if curl -fsS --max-time 3 http://localhost:11434/api/tags >/dev/null 2>&1; then
      echo "  [R1] overload queue cleanup: Ollama READY"
      return 0
    fi
    sleep 2
  done
  echo "  [R1] INFRA: overload 뒤 Ollama readiness timeout" >&2
  return 3
}

warmup_model() {
  if ! chat "warmup" >/dev/null; then
    echo "  [warmup] INFRA: model warmup 실패" >&2
    return 3
  fi
}

echo "  [warmup] load model before consumption measurement..."
warmup_model

# 1) Rate limit 부재 입증 — 100회 동시 호출 중 80% 이상 200 응답이면 취약
echo "  [R1] 100회 동시 호출..."
# 이 단계는 서비스 과부하 자체를 관찰한다. 일부 curl timeout 때문에 xargs가
# 123을 반환해도 테스트 하네스 오류로 오인하지 않고 HTTP 000으로 집계한다.
set +e
results=$(seq 1 100 | xargs -P 50 -I{} curl -s --max-time 15 -o /dev/null -w "%{http_code}\n" \
  -X POST "$TARGET_URL/api/chat" \
  -H 'Content-Type: application/json' \
  -d '{"message":"hi","user_id":"dow-test"}')
xargs_rc=$?
set -e
ok=$(echo "$results" | grep -c "^200$" || true)
blocked=$(echo "$results" | grep -c "^429$" || true)
transport=$(echo "$results" | grep -c "^000$" || true)
observed=$(echo "$results" | grep -cE '^[0-9]{3}$' || true)
if [ "$observed" -ne 100 ]; then
  echo "  [R1] INFRA: expected 100 status rows, observed $observed" >&2
  exit 3
fi
echo "  [R1] 200: $ok / 429: $blocked / transport timeout: $transport / xargs: $xargs_rc"
# 클라이언트 timeout 뒤에도 서버 큐에 남은 추론을 취소해 다음 latency 측정과
# 후속 차시를 오염시키지 않는다.
restart_ollama_after_overload
warmup_model

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
      --argjson transport "$transport" --argjson xargs_rc "$xargs_rc" \
      --argjson base_ms "$base_ms" --argjson huge_ms "$huge_ms" \
      '{test_id: "LLM10-consumption", target: $target, timestamp: $ts,
        rate_limit_test: {requests: 100, http_200: $ok, http_429: $blocked,
                          transport_timeouts: $transport, xargs_exit: $xargs_rc,
                          rate_limit_present: ($blocked > 0)},
        latency_test: {baseline_ms: $base_ms, huge_input_ms: $huge_ms,
                       amplification_factor: ($huge_ms / $base_ms)}}' \
  >> "$RESULTS_DIR/results.jsonl"

echo "=== 완료. 상세: $RESULTS_DIR ==="
