#!/bin/bash
# LLM03 Supply Chain — fake model-registry SHA-256 mismatch 검출
# D-13 (2026-05-23) 추가. lab-fake-registry 컨테이너 (port 8002) 자동 검증.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 인스턴스 안에서 실행되는 경우 host 직접 접근 — common.sh 의 require_healthy 미사용 (fake-registry는 SG에 미공개, 인스턴스 내부 only)
REGISTRY="${REGISTRY:-http://localhost:8002}"
python3 "$SCRIPT_DIR/../lib/require_loopback_url.py" "$REGISTRY" || exit 2
: "${RESULTS_DIR:=tests/e2e/results/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$RESULTS_DIR/raw"

PASS=0
FAIL=0

fetch_registry() {
  if ! curl -fsS --max-time 10 "$@"; then
    echo "INFRA: fake registry request failed: $REGISTRY" >&2
    exit 3
  fi
}

check() {
  local name="$1"
  shift
  if "$@"; then
    echo "  PASS: $name"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $name"
    FAIL=$((FAIL + 1))
  fi
}

models_has_clean() {
  printf '%s' "$MODELS_JSON" | jq -e '.models[] | select(.id == "A") | .trusted == true' >/dev/null
}

models_has_trojan() {
  printf '%s' "$MODELS_JSON" | jq -e '.models[] | select(.id == "B") | .trusted == false' >/dev/null
}

mlbom_has_cwe() {
  printf '%s' "$MLBOM" | jq -e '.vulnerabilities[] | select(. | contains("CWE-1395"))' >/dev/null
}

mlbom_has_base_model() {
  printf '%s' "$MLBOM" | jq -e '.components[] | select(.name == "base_model")' >/dev/null
}

echo "=== LLM03 Supply Chain — fake model-registry 검증 ==="
echo "REGISTRY=$REGISTRY"
echo ""

# Part 1: 모델 목록 응답
echo "[Part 1] 모델 카드 정찰"
MODELS_JSON=$(fetch_registry "$REGISTRY/api/v1/models")
printf '%s\n' "$MODELS_JSON" > "$RESULTS_DIR/raw/models.json"
check "/api/v1/models 응답 존재" test -n "$MODELS_JSON"
check "응답에 모델 A (clean) 포함" models_has_clean
check "응답에 모델 B (trojan) 포함" models_has_trojan
echo ""

# Part 2: SHA-256 mismatch 검출 (핵심 학습 목표)
echo "[Part 2] SHA-256 무결성 검증"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# A: clean — 일치해야 함
EXPECTED_A=$(fetch_registry "$REGISTRY/api/v1/models/A" | jq -er .sha256)
fetch_registry -L "$REGISTRY/models/A.gguf" -o "$TMPDIR/A.gguf"
ACTUAL_A=$(sha256sum "$TMPDIR/A.gguf" | cut -d' ' -f1)
check "Model A claim == actual SHA-256 (clean 일치)" test "$EXPECTED_A" = "$ACTUAL_A"

# B: trojan — mismatch 발생해야 함
EXPECTED_B=$(fetch_registry "$REGISTRY/api/v1/models/B" | jq -er .sha256)
fetch_registry -L "$REGISTRY/models/B.gguf" -o "$TMPDIR/B.gguf"
ACTUAL_B=$(sha256sum "$TMPDIR/B.gguf" | cut -d' ' -f1)
printf 'model_a_expected=%s\nmodel_a_actual=%s\nmodel_b_expected=%s\nmodel_b_actual=%s\n' \
  "$EXPECTED_A" "$ACTUAL_A" "$EXPECTED_B" "$ACTUAL_B" \
  > "$RESULTS_DIR/raw/integrity.txt"
check "Model B claim != actual SHA-256 (trojan 검출)" test "$EXPECTED_B" != "$ACTUAL_B"
echo "  (claim:  $EXPECTED_B)"
echo "  (actual: $ACTUAL_B)"
echo ""

# Part 5: MLBOM
echo "[Part 5] MLBOM 조회"
MLBOM=$(fetch_registry "$REGISTRY/api/v1/models/B/mlbom")
printf '%s\n' "$MLBOM" > "$RESULTS_DIR/raw/mlbom.json"
check "MLBOM 응답 존재" test -n "$MLBOM"
check "MLBOM에 CWE-1395 포함" mlbom_has_cwe
check "MLBOM에 base_model component 포함" mlbom_has_base_model
echo ""

echo "=== 결과: PASS=$PASS, FAIL=$FAIL ==="
TOTAL=$((PASS + FAIL))
RATE=$((PASS * 100 / TOTAL))
jq -n \
  --arg target "$REGISTRY" \
  --arg ts "$(date -Iseconds)" \
  --argjson pass "$PASS" \
  --argjson fail "$FAIL" \
  --argjson trials "$TOTAL" \
  --argjson rate "$RATE" \
  '{test_id:"LLM03-registry-integrity", target:$target, timestamp:$ts,
    trials:$trials, pass:$pass, fail:$fail, success_rate_pct:$rate}' \
  >> "$RESULTS_DIR/results.jsonl"

[ "$FAIL" -eq 0 ]
