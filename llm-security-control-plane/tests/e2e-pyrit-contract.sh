#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NETWORK=module08-pyrit-contract
BOUNDARIES=module08-pyrit-boundaries

cleanup() {
  docker rm -f "$BOUNDARIES" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build -f "$ROOT/examples/day6/pyrit-guardrail/Containerfile" \
  -t localhost/module08-pyrit:1.0.1 "$ROOT/examples/day6/pyrit-guardrail"
docker network create "$NETWORK" >/dev/null
docker run -d --name "$BOUNDARIES" --network "$NETWORK" \
  --network-alias llm-security-application-gateway \
  --network-alias llm-security-bedrock-gateway \
  -v "$ROOT/llm-security-control-plane/tests/fake_pyrit_boundaries.py:/app/server.py:ro" \
  docker.io/library/python:3.12-slim python /app/server.py >/dev/null

for _attempt in 1 2 3 4 5; do
  if docker run --rm --network "$NETWORK" --entrypoint python \
    localhost/module08-pyrit:1.0.1 -c '
import urllib.request
urllib.request.urlopen("http://llm-security-bedrock-gateway:8080/healthz", timeout=2)' \
    >/dev/null 2>&1; then
    break
  fi
done

result="$(docker run --rm --network "$NETWORK" \
  -e APPLICATION_ACCESS_TOKEN=pyrit-application-contract-token \
  -e BEDROCK_GATEWAY_TOKEN=pyrit-bedrock-contract-token \
  localhost/module08-pyrit:1.0.1)"

jq -e '
  .pyrit_outcome == "failure" and
  .objective_score == false and
  .executed_turns == 3 and
  (.turns | length) == 3 and
  ([.turns[].prompt] | unique | length) == 3 and
  ([.turns[].request_id] | unique | length) == 3 and
  ([.turns[] |
    .application_decision == "allow" and
    .blocking_reason == null and
    .upstream_called == true and
    .detected_stage == null] | all)
' <<<"$result" >/dev/null

assert_err() {
  local app_token=$1
  local expected_status=$2
  local output
  local exit_code
  set +e
  output="$(docker run --rm --network "$NETWORK" \
    -e "APPLICATION_ACCESS_TOKEN=$app_token" \
    -e BEDROCK_GATEWAY_TOKEN=pyrit-bedrock-contract-token \
    localhost/module08-pyrit:1.0.1)"
  exit_code=$?
  set -e
  test "$exit_code" -ne 0
  jq -e --argjson status "$expected_status" '
    .pyrit_outcome == "error" and
    .course_verdict == "ERR" and
    .http_status == $status
  ' <<<"$output" >/dev/null
}

assert_err pyrit-application-401-token 401
assert_err pyrit-application-422-token 422
assert_err pyrit-application-500-token 500

set +e
python_error="$(docker run --rm --network "$NETWORK" \
  -e BEDROCK_GATEWAY_TOKEN=pyrit-bedrock-contract-token \
  localhost/module08-pyrit:1.0.1)"
python_exit=$?
set -e
test "$python_exit" -ne 0
jq -e '
  .pyrit_outcome == "error" and
  .course_verdict == "ERR" and
  .error_type == "KeyError" and
  .http_status == null
' <<<"$python_error" >/dev/null

printf 'module08-pyrit-contract=PASS actual-pyrit bounded-turns=3 errors=401,422,500,python\n'
