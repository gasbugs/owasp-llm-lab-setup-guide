#!/bin/bash
# LLM01 direct-input-only regression — no RAG corpus or retrieved context.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

require_healthy
require_scenario "day1"

echo "=== LLM01 RAG 제거 검증 ==="

request_file="$RESULTS_DIR/llm01-no-rag-request.json"
response_file="$RESULTS_DIR/llm01-no-rag-response.json"
inject_file="$RESULTS_DIR/llm01-no-rag-inject.json"

printf '%s\n' '{"message":"Hello, please translate this sentence.","scenario":"day1"}' >"$request_file"
curl -sS --max-time 180 -X POST "$TARGET_URL/api/chat" \
  -H 'Content-Type: application/json' \
  --data-binary "@$request_file" \
  -o "$response_file"

jq -e '
  .scenario == "day1"
  and (.reply | type == "string" and length > 0)
  and (.debug | has("retrieved_chunks") | not)
' "$response_file" >/dev/null

printf '%s\n' '{"scenario":"day1","title":"must-not-store","text":"unused"}' >"$inject_file"
status="$(curl -sS --max-time 30 -o "$RESULTS_DIR/llm01-no-rag-inject-response.json" \
  -w '%{http_code}' -X POST "$TARGET_URL/api/admin/inject-doc" \
  -H 'Content-Type: application/json' \
  --data-binary "@$inject_file")"

if [ "$status" != "404" ]; then
  echo "expected LLM01 document injection to return HTTP 404, got $status" >&2
  exit 1
fi

jq -e '.detail == "RAG is not enabled for LLM01"' \
  "$RESULTS_DIR/llm01-no-rag-inject-response.json" >/dev/null

echo "=== LLM01 RAG 제거 검증 완료 ==="
