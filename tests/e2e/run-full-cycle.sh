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
: "${GOAT_URL:=http://localhost:5000}"

runtime_uid=$(id -u)
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$runtime_uid}"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}"

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
declare -A BASELINE_DOC_COUNTS=(
  ["day1"]=2
  ["day2"]=2
  ["day3"]=2
  ["day4"]=4
  ["day5"]=3
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
  local sentinel="E2E_RESET_SENTINEL_${TS}"
  local services=(
    lab-day1-vuln-rag.service
    lab-day2-vuln-rag.service
    lab-day3-vuln-rag.service
    lab-day4-vuln-rag.service
    lab-day5-vuln-rag.service
  )
  if ! command -v systemctl >/dev/null 2>&1; then
    log "  ✗ systemctl 없음: Quadlet 서비스를 기준선으로 복원할 수 없음"
    return 1
  fi

  # restart가 실제로 메모리 내 오염 문서를 버리는지 sentinel로 검증한다.
  local scenario url
  for scenario in day1 day2 day3 day4 day5; do
    url="${SCENARIO_URLS[$scenario]}"
    if ! curl -fsS --max-time 10 -X POST "$url/api/admin/inject-doc" \
      -H 'Content-Type: application/json' \
      -d "$(jq -n --arg title "$sentinel" --arg text "$sentinel" \
        '{title: $title, text: $text}')" \
      | jq -e '.ok == true' >/dev/null; then
      log "  ✗ $scenario reset sentinel 주입 실패"
      return 1
    fi
  done
  if ! systemctl --user restart "${services[@]}"; then
    log "  ✗ RAG Quadlet service restart 실패"
    return 1
  fi

  local clean baseline count expected
  for scenario in day1 day2 day3 day4 day5; do
    url="${SCENARIO_URLS[$scenario]}"
    expected="${BASELINE_DOC_COUNTS[$scenario]}"
    clean=false
    for _ in $(seq 1 30); do
      if baseline=$(curl -fsS --max-time 5 "$url/api/admin/docs" 2>/dev/null) \
        && printf '%s' "$baseline" \
          | jq -e --argjson expected "$expected" --arg sentinel "$sentinel" '
              .ok == true
              and (.docs | type == "array")
              and (.docs | length == $expected)
              and ([.docs[].text | contains($sentinel)] | any | not)
            ' >/dev/null; then
        count=$(printf '%s' "$baseline" | jq -r '.docs | length')
        log "  ✓ $scenario clean restart baseline docs=$count"
        clean=true
        break
      fi
      sleep 2
    done
    if [ "$clean" != "true" ]; then
      log "  ✗ $scenario clean baseline 확인 실패 (expected docs=$expected, sentinel must be absent)"
      return 1
    fi
  done

  if ! systemctl --user restart lab-day3-vuln-agent.service; then
    log "  ✗ Agent Quadlet service restart 실패"
    return 1
  fi
  for _ in $(seq 1 30); do
    if curl -fsS --max-time 5 "$AGENT_URL/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  local agent_state="$RESULTS_DIR/agent-baseline-state.json"
  if ! curl -fsS --max-time 10 "$AGENT_URL/api/admin/state" -o "$agent_state" \
    || ! jq -e '
      .ok == true
      and ([.animals[].animal_id] | index("g-003") != null)
      and .deleted_log == []
    ' "$agent_state" >/dev/null; then
    log "  ✗ Agent service restart 기준선 확인 실패"
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

# === LLMGoat — A01/A02/A04/A06/A08 complete API + state contracts ===
run_llmgoat() {
  log "▶ LLMGoat cross-platform API/state e2e"
  local item_dir="$RESULTS_DIR/llmgoat"
  mkdir -p "$item_dir"
  RESULTS_DIR="$item_dir" TRIALS="$TRIALS" GOAT_URL="$GOAT_URL" \
    bash "$SCRIPT_DIR/llmgoat/run-all.sh" 2>&1 \
    | tee "$item_dir/output.txt" | tail -5
  local status=${PIPESTATUS[0]}
  if [ "$status" -ne 0 ]; then
    log "  ✗ LLMGoat API/state 검증 실패 (exit=$status)"
    FAILED_STEPS+=("e2e:llmgoat")
  elif ! jq -e '.status == "PASS"' "$item_dir/summary.json" >/dev/null; then
    log "  ✗ LLMGoat summary.json PASS 계약 누락"
    FAILED_STEPS+=("e2e:llmgoat-summary")
  else
    log "  ✓ LLMGoat API/state 검증 PASS (model solved rate는 관찰값)"
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
run_llmgoat

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
        if .outcome_policy == "observation-only" then
          "\(.test_id): solved=\(.solved_count) unsolved=\(.unsolved_count) infra=\(.infra_fail) trials=\(.trials_attempted)/\(.trials) (\(.solved_rate_pct)% observed)"
        elif has("pass") and has("trials") and has("success_rate_pct") then
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

if [ -f "$RESULTS_DIR/llmgoat/state-contracts.jsonl" ]; then
  echo "--- $RESULTS_DIR/llmgoat/state-contracts.jsonl ---" \
    | tee -a "$RESULTS_DIR/summary.txt"
  jq -r '
    "\(.challenge): contract=\(.contract) pass=\(.pass) before=\(.before_sha256) mutated=\(.mutated_sha256) restored=\(.restored_sha256)"
  ' "$RESULTS_DIR/llmgoat/state-contracts.jsonl" \
    | tee -a "$RESULTS_DIR/summary.txt"
fi

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
