#!/bin/bash
# Complete loopback-only LLMGoat API validation stage.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${RESULTS_DIR:=$SCRIPT_DIR/../results/$(date +%Y%m%d-%H%M%S)-llmgoat}"
: "${TRIALS:=3}"
: "${GOAT_URL:=http://localhost:5000}"

mkdir -p "$RESULTS_DIR"
rm -rf "$RESULTS_DIR/raw" "$RESULTS_DIR/state" "$RESULTS_DIR/.cookies"
rm -f "$RESULTS_DIR/results.jsonl" "$RESULTS_DIR/state-contracts.jsonl" \
  "$RESULTS_DIR/summary.json" "$RESULTS_DIR/sha256sums.txt"
touch "$RESULTS_DIR/results.jsonl"

echo "=== LLMGoat complete API validation (TRIALS=$TRIALS) ==="
RESULTS_DIR="$RESULTS_DIR" TRIALS="$TRIALS" GOAT_URL="$GOAT_URL" \
  bash "$SCRIPT_DIR/test_a01_prompt_injection.sh"
RESULTS_DIR="$RESULTS_DIR" TRIALS="$TRIALS" GOAT_URL="$GOAT_URL" \
  bash "$SCRIPT_DIR/test_a02_a04_a06_a08.sh"

if ! jq -s -e '
    length == 9
    and ([.[].challenge] | unique | sort == [
      "a01-prompt-injection",
      "a02-sensitive-information-disclosure",
      "a04-data-and-model-poisoning",
      "a06-excessive-agency",
      "a08-vector-embedding-weaknesses"
    ])
    and all(
      .outcome_policy == "observation-only"
      and .verdict == "OBSERVED"
      and .infra_fail == 0
      and .trials_attempted == .trials
    )
  ' "$RESULTS_DIR/results.jsonl" >/dev/null; then
  echo "ERROR: LLMGoat observation summary contract failed" >&2
  exit 1
fi
if ! jq -s -e '
    length == 2
    and all(.outcome_policy == "deterministic-contract" and .pass == true)
    and ([.[].challenge] | sort == [
      "a04-data-and-model-poisoning",
      "a08-vector-embedding-weaknesses"
    ])
  ' "$RESULTS_DIR/state-contracts.jsonl" >/dev/null; then
  echo "ERROR: LLMGoat mutable-state reset contract failed" >&2
  exit 1
fi
if [ -s "$RESULTS_DIR/raw/contract-errors.jsonl" ]; then
  echo "ERROR: LLMGoat response contract errors were recorded" >&2
  exit 1
fi
if ! jq -s -e 'length > 0 and all(.infra_ok == true)' \
  "$RESULTS_DIR/raw/requests.jsonl" >/dev/null; then
  echo "ERROR: LLMGoat raw request evidence is missing or contains infra failures" >&2
  exit 1
fi
if [ -e "$RESULTS_DIR/.cookies" ]; then
  echo "ERROR: LLMGoat cookie/session evidence was not cleaned" >&2
  exit 1
fi

observation_count=$(jq -s 'length' "$RESULTS_DIR/results.jsonl")
raw_request_count=$(jq -s 'length' "$RESULTS_DIR/raw/requests.jsonl")
state_contract_count=$(jq -s 'length' "$RESULTS_DIR/state-contracts.jsonl")
results_sha=$(sha256sum "$RESULTS_DIR/results.jsonl" | awk '{print $1}')
raw_sha=$(sha256sum "$RESULTS_DIR/raw/requests.jsonl" | awk '{print $1}')
state_sha=$(sha256sum "$RESULTS_DIR/state-contracts.jsonl" | awk '{print $1}')
jq -n \
  --arg status PASS \
  --arg target "$GOAT_URL" \
  --arg completed_at "$(date -Iseconds)" \
  --arg results_sha256 "$results_sha" \
  --arg raw_requests_sha256 "$raw_sha" \
  --arg state_contracts_sha256 "$state_sha" \
  --argjson trials "$TRIALS" \
  --argjson observation_count "$observation_count" \
  --argjson raw_request_count "$raw_request_count" \
  --argjson state_contract_count "$state_contract_count" \
  '{schema:"owasp-llm-llmgoat-validation/v1",status:$status,target:$target,
    completed_at:$completed_at,trials:$trials,
    policy:{model_solved_rate:"observation-only",
      mutable_state:"deterministic-fail-closed"},
    counts:{observations:$observation_count,raw_requests:$raw_request_count,
      state_contracts:$state_contract_count},
    evidence:{results_jsonl_sha256:$results_sha256,
      raw_requests_jsonl_sha256:$raw_requests_sha256,
      state_contracts_jsonl_sha256:$state_contracts_sha256}}' \
  >"$RESULTS_DIR/summary.json"

(
  cd "$RESULTS_DIR"
  find . -type f ! -name sha256sums.txt -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum >sha256sums.txt
)

echo "PASS: LLMGoat API, state reset, and raw evidence contracts passed"
echo "Evidence: $RESULTS_DIR"
