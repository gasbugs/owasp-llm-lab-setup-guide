#!/bin/bash
# OWASP Top 10 for LLM — 전체 e2e 테스트 스위트
#
# 사용:
#   bash tests/e2e/run-all.sh                # 모든 테스트
#   bash tests/e2e/run-all.sh llm01 llm02    # 특정 항목만
#
# 환경변수:
#   TARGET_URL   기본은 항목별 고정 포트. 직접 지정하면 지정값 우선
#   AGENT_URL    기본 http://localhost:8001
#   TRIALS       기본 5
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 결과 디렉터리 (오버라이드 가능)
: "${RESULTS_DIR:=$SCRIPT_DIR/results/$(date +%Y%m%d-%H%M%S)}"
export RESULTS_DIR

# 인자가 있으면 그 항목만, 없으면 전체
if [ "$#" -gt 0 ]; then
  ITEMS=("$@")
else
  ITEMS=(llm01 llm02 llm03 llm04 llm05 llm06 llm07 llm08 llm09 llm10)
fi

target_for_item() {
  case "$1" in
    llm01) echo "http://localhost:8000" ;;
    llm02|llm04) echo "http://localhost:8010" ;;
    llm05) echo "http://localhost:8011" ;;
    llm07|llm08|llm09) echo "http://localhost:8012" ;;
    llm10) echo "http://localhost:8013" ;;
    *) echo "${TARGET_URL:-http://localhost:8000}" ;;
  esac
}

mkdir -p "$RESULTS_DIR"
echo "=== OWASP Top 10 for LLM — e2e 검증 ==="
echo "결과 디렉터리: $RESULTS_DIR"
echo

failed=()

for item in "${ITEMS[@]}"; do
  # 항목별 live shell test와 source-level Python regression을 함께 실행한다.
  scripts=(
    "$SCRIPT_DIR/$item"/test_*.sh
    "$SCRIPT_DIR/$item"/test_*.py
  )
  found=false
  for s in "${scripts[@]}"; do
    [ -f "$s" ] || continue
    found=true
    case "$s" in
      *.sh) runner=(bash "$s") ;;
      *.py) runner=(python3 "$s") ;;
      *) continue ;;
    esac
    echo "▶ $(basename "$s")"
    if TARGET_URL="${TARGET_URL:-$(target_for_item "$item")}" "${runner[@]}"; then
      echo "  ✓ OK"
    else
      status=$?
      echo "  ✗ FAIL (exit code $status)"
      failed+=("$s")
    fi
    echo
  done
  if [ "$found" = false ]; then
    echo "[$item] 테스트 스크립트 없음, 건너뜀"
  fi
done

# 결과 요약 markdown
SUMMARY="$RESULTS_DIR/summary.md"
{
  echo "# e2e 테스트 결과"
  echo
  echo "- 실행 시각: $(date -Iseconds)"
  echo "- TARGET_URL: 항목별 고정 포트 사용"
  echo "- AGENT_URL:  ${AGENT_URL:-http://localhost:8001}"
  echo "- TRIALS:     ${TRIALS:-5}"
  echo
  echo "## 페이로드별 성공률"
  echo
  echo "| Test ID | Pass | Fail | Infra | Trials | 성공률 | 페이로드 파일 |"
  echo "|---|---:|---:|---:|---:|---:|---|"
  if [ -f "$RESULTS_DIR/results.jsonl" ]; then
    jq -r '
      if has("pass") and has("trials") and has("success_rate_pct") then
        "| \(.test_id) | \(.pass) | \(.fail // "n/a") | \(.infra_fail // 0) | \(.trials) | \(.success_rate_pct)% | \(.payload_file // "—") |"
      else
        "| \(.test_id) | n/a | n/a | \(.infra_fail // 0) | n/a | n/a | \(.payload_file // "—") |"
      end
    ' \
       "$RESULTS_DIR/results.jsonl"
  fi
  echo
  echo "## 실패한 테스트 스크립트"
  if [ "${#failed[@]}" -gt 0 ]; then
    printf -- "- %s\n" "${failed[@]}"
  else
    echo "(없음)"
  fi
} > "$SUMMARY"

echo "=== 완료 ==="
echo "요약: $SUMMARY"
cat "$SUMMARY"

[ "${#failed[@]}" -eq 0 ] || exit 1
