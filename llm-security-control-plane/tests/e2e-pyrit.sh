#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

set -a
. "$ROOT/.state/module08-compose.env"
set +a

access_token="$(docker run --rm --network llm-security-control-plane \
  --entrypoint python localhost/module08-pyrit:1.0.1 -c '
import json, urllib.request
request = urllib.request.Request(
    "http://llm-security-application-gateway:8000/.well-known/login",
    data=b"{\"username\":\"public-reader\",\"password\":\"public-reader-demo\"}",
    headers={"Content-Type": "application/json"}, method="POST")
print(json.load(urllib.request.urlopen(request, timeout=10))["access_token"])')"
normal="$(docker run --rm --network llm-security-control-plane \
  -e "APPLICATION_ACCESS_TOKEN=$access_token" \
  --entrypoint python localhost/module08-pyrit:1.0.1 -c '
import json, os, urllib.request
request = urllib.request.Request(
    "http://llm-security-application-gateway:8000/api/chat",
    data=b"{\"message\":\"Give a short password reset checklist.\",\"classification\":\"none\",\"purpose\":\"public_information\"}",
    headers={"Authorization": "Bearer " + os.environ["APPLICATION_ACCESS_TOKEN"],
             "Content-Type": "application/json"}, method="POST")
print(json.dumps(json.load(urllib.request.urlopen(request, timeout=360))))')"
jq -e '.application_decision == "allow" and .upstream_called == true' <<<"$normal" >/dev/null

result="$(docker run --rm --network llm-security-control-plane \
  -e "APPLICATION_ACCESS_TOKEN=$access_token" \
  -e "BEDROCK_GATEWAY_TOKEN=$BEDROCK_GATEWAY_TOKEN" \
  localhost/module08-pyrit:1.0.1)"

jq -e '
  (.executed_turns >= 2 and .executed_turns <= 3) and
  (.turns | length) == .executed_turns and
  ([.turns[].request_id] | unique | length) == .executed_turns and
  ([.turns[].prompt] | unique | length) == .executed_turns and
  ([.turns[] | .application_decision == "allow" and .upstream_called == true] | all)
' <<<"$result" >/dev/null
printf 'module08-pyrit=PASS bounded-multi-turn\n'
