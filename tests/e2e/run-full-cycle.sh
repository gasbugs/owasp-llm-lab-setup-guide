#!/bin/bash
# 전체 lab runtime 시나리오를 자동 순회하며 e2e 결과를 로컬 EBS에 저장.
#
# 사용 (강사용 live validation workspace 안에서):
#   sudo -u ubuntu TRIALS=5 bash tests/e2e/run-full-cycle.sh
#
set -uo pipefail

# sudo·SSM 환경에서 $HOME 미설정 가능 (set -u에서 fail). 명시적 default
: "${HOME:=/home/ubuntu}"
export HOME

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$(dirname "$SCRIPT_DIR")/.." && pwd)"
cd "$REPO_ROOT"

# 설치 시 기록한 런타임 정보를 가져온다.
[ -f /etc/lab/env ] && source /etc/lab/env

: "${AWS_DEFAULT_REGION:=us-east-1}"
: "${TRIALS:=5}"
: "${AGENT_URL:=http://localhost:8001}"

TS=$(date +%Y%m%d-%H%M%S)
RESULTS_DIR="$HOME/work/e2e-evidence/$TS"
mkdir -p "$RESULTS_DIR"
FAILED_STEPS=()

log() {
  printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*" | tee -a "$RESULTS_DIR/log.txt"
}

# 런타임 서비스별 고정 포트 + 실행할 e2e 항목.
# LLM08은 Day 2 차시지만 shared PrivateGPT-Lite 서비스(day4/8012)를 사용한다.
# LLM03은 RAG scenario가 아니라 독립 registry(8002)이므로 아래 map 밖에서 실행한다.
declare -A SCENARIO_ITEMS=(
  ["day1"]="llm01"
  ["day2"]="llm02 llm04"
  ["day3"]="llm05"
  ["day4"]="llm07 llm08 llm09"
  ["day5"]="llm10"
)
# 파괴적 Agent 검증 뒤, 자원 소비 LLM10을 전체 cycle의 마지막에 실행한다.
SCENARIO_ORDER=(day1 day2 day3 day4)
declare -A SCENARIO_URLS=(
  ["day1"]="http://localhost:8000"
  ["day2"]="http://localhost:8010"
  ["day3"]="http://localhost:8011"
  ["day4"]="http://localhost:8012"
  ["day5"]="http://localhost:8013"
)

require_day_ready() {
  local scenario="$1"
  local url="${SCENARIO_URLS[$scenario]}"
  log "▶ scenario 확인: $scenario ($url)"
  for i in $(seq 1 30); do
    if [ "$(curl -fsS --max-time 5 "$url/healthz" 2>/dev/null | jq -r '.default_scenario // .scenario // "unknown"')" = "$scenario" ]; then
      log "  ✓ $scenario READY"
      return 0
    fi
    sleep 5
  done
  log "  ✗ $scenario 서비스 확인 실패: $url"
  return 1
}

reset_mutable_state() {
  log "▶ mutable runtime 기준선 복원"
  local containers=(
    lab-day1-vuln-rag
    lab-day2-vuln-rag
    lab-day3-vuln-rag
    lab-day4-vuln-rag
    lab-day5-vuln-rag
  )
  if ! command -v podman >/dev/null 2>&1; then
    log "  ✗ podman 없음: shared corpus를 재현 가능한 기준선으로 복원할 수 없음"
    return 1
  fi
  if ! podman restart "${containers[@]}" >/dev/null; then
    log "  ✗ RAG 컨테이너 restart 실패"
    return 1
  fi

  local scenario url clean
  for scenario in day1 day2 day3 day4 day5; do
    url="${SCENARIO_URLS[$scenario]}"
    clean=false
    for _ in $(seq 1 30); do
      if curl -fsS --max-time 5 "$url/api/admin/docs" 2>/dev/null \
        | jq -e '.docs | length == 0' >/dev/null; then
        clean=true
        break
      fi
      sleep 2
    done
    if [ "$clean" != "true" ]; then
      log "  ✗ $scenario shared corpus baseline 확인 실패"
      return 1
    fi
  done

  for _ in $(seq 1 30); do
    if curl -fsS --max-time 5 "$AGENT_URL/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  if ! curl -fsS --max-time 10 -X POST "$AGENT_URL/api/admin/reset" \
    | jq -e '.ok == true and (.animals | index("g-003") != null)' >/dev/null; then
    log "  ✗ Agent 기준선 reset 실패"
    return 1
  fi
  log "  ✓ shared corpus 5개와 Agent 상태 기준선 확인"
}

# === LLM03 — 독립 fake registry (port 8002) ===
run_registry() {
  log "▶ fake registry (Day 4 LLM03) e2e"
  local item_dir="$RESULTS_DIR/llm03"
  mkdir -p "$item_dir"
  RESULTS_DIR="$item_dir" TRIALS="$TRIALS" \
    bash "$SCRIPT_DIR/run-all.sh" llm03 2>&1 \
    | tee "$item_dir/output.txt" | tail -3
  local status=${PIPESTATUS[0]}
  if [ "$status" -ne 0 ]; then
    log "  ✗ fake registry LLM03 실패 (exit=$status)"
    FAILED_STEPS+=("e2e:llm03")
  fi
}

run_items() {
  local scenario="$1"
  local items="$2"
  for item in $items; do
    local item_dir="$RESULTS_DIR/$item"
    mkdir -p "$item_dir"
    log "  ▶ e2e $item (scenario=$scenario)"
    RESULTS_DIR="$item_dir" TRIALS="$TRIALS" TARGET_URL="${SCENARIO_URLS[$scenario]}" \
      bash "$SCRIPT_DIR/run-all.sh" "$item" 2>&1 \
      | tee "$item_dir/output.txt" \
      | tail -3
    local status=${PIPESTATUS[0]}
    if [ "$status" -ne 0 ]; then
      log "  ✗ e2e $item 실패 (exit=$status)"
      FAILED_STEPS+=("e2e:$item")
    fi
  done
}

# === LLM06 — vuln-agent (이미 부팅 시 떠있음) ===
run_agent() {
  log "▶ vuln-agent (LLM06) e2e"
  local item_dir="$RESULTS_DIR/llm06"
  mkdir -p "$item_dir"
  RESULTS_DIR="$item_dir" TRIALS="$TRIALS" \
    bash "$SCRIPT_DIR/run-all.sh" llm06 2>&1 \
    | tee "$item_dir/output.txt" | tail -3
  local status=${PIPESTATUS[0]}
  if [ "$status" -ne 0 ]; then
    log "  ✗ vuln-agent LLM06 실패 (exit=$status)"
    FAILED_STEPS+=("e2e:llm06")
  fi
}

# === 실행 ===
log "============================================"
log "  OWASP Top 10 for LLM — Full Cycle e2e"
log "  STUDENT=${STUDENT:-?} TRIALS=$TRIALS"
log "============================================"

if ! reset_mutable_state; then
  log "FAIL: 기준선 복원 실패로 full-cycle을 시작하지 않음"
  exit 1
fi

for scenario in "${SCENARIO_ORDER[@]}"; do
  if require_day_ready "$scenario"; then
    run_items "$scenario" "${SCENARIO_ITEMS[$scenario]}"
  else
    FAILED_STEPS+=("scenario:$scenario")
  fi
done

run_registry
run_agent

# LLM10은 동시 요청으로 Ollama queue를 점유할 수 있으므로 반드시 마지막에 실행한다.
if require_day_ready day5; then
  run_items day5 "${SCENARIO_ITEMS[day5]}"
else
  FAILED_STEPS+=("scenario:day5")
fi

log "============================================"
log "  완료. 결과: $RESULTS_DIR"
log "============================================"

# Summary
echo "=== 전체 e2e 요약 ===" | tee -a "$RESULTS_DIR/summary.txt"
for d in "$RESULTS_DIR"/llm*/results.jsonl; do
  [ -f "$d" ] || continue
  echo "--- $d ---" | tee -a "$RESULTS_DIR/summary.txt"
  case "$d" in
    *.jsonl)
      jq -r '
        if has("pass") and has("trials") and has("success_rate_pct") then
          "\(.test_id): pass=\(.pass) fail=\(.fail // "n/a") infra=\(.infra_fail // 0) trials=\(.trials) (\(.success_rate_pct)%)"
        else
          "\(.test_id): structured result recorded"
        end
      ' "$d" 2>/dev/null \
        | tee -a "$RESULTS_DIR/summary.txt"
      ;;
    *.txt)
      tail -15 "$d" | tee -a "$RESULTS_DIR/summary.txt"
      ;;
  esac
done

if [ "${#FAILED_STEPS[@]}" -gt 0 ]; then
  {
    echo
    echo "## 실패한 full-cycle 단계"
    printf -- "- %s\n" "${FAILED_STEPS[@]}"
  } | tee -a "$RESULTS_DIR/summary.txt"
  log "FAIL: ${#FAILED_STEPS[@]}개 단계 실패"
  exit 1
fi

log "PASS: full-cycle 모든 단계 통과"
