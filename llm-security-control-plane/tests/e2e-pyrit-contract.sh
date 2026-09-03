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

printf 'module08-pyrit-contract=PASS actual-pyrit bounded-turns=3\n'
