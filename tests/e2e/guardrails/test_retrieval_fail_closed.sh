#!/usr/bin/env bash
set -euo pipefail

NET="retrieval-contract-$$"
PRESIDIO="retrieval-presidio-$$"
NEMO="retrieval-nemo-$$"
PRESIDIO_IMAGE="${PRESIDIO_IMAGE:-localhost/guardrails-presidio:2.2.362}"
NEMO_IMAGE="${NEMO_IMAGE:-localhost/llm-security-nemo-dialog-rails:0.24.1}"
cleanup() {
  docker rm -f "$NEMO" "$PRESIDIO" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "$NET" >/dev/null
docker run -d --name "$PRESIDIO" --network "$NET" \
  --network-alias guardrails-presidio-api \
  -e RUN_MODE=server -e GUARD_MODE=prevent -e ENABLE_LAB_ENDPOINTS=true \
  "$PRESIDIO_IMAGE" >/dev/null
docker run -d --name "$NEMO" --network "$NET" \
  -e RUN_MODE=server -e GUARD_MODE=prevent -e ENABLE_LAB_ENDPOINTS=true \
  -e PRESIDIO_URL=http://guardrails-presidio-api:8013 \
  -e MODEL_GATEWAY_URL=http://unavailable-gateway:8080 \
  -e BEDROCK_GATEWAY_TOKEN=isolated-test-token \
  "$NEMO_IMAGE" >/dev/null

for _ in $(seq 1 90); do
  if docker exec "$PRESIDIO" python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8013/healthz", timeout=2)' >/dev/null 2>&1 \
    && docker exec "$NEMO" python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8013/healthz", timeout=2)' >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

docker exec -i "$NEMO" python - <<'PY'
import json
import urllib.request

request = urllib.request.Request(
    'http://127.0.0.1:8013/api/labs/retrieval',
    data=json.dumps({'chunks': ['Contact alice@example.com for help.']}).encode(),
    headers={'Content-Type': 'application/json'},
)
with urllib.request.urlopen(request, timeout=120) as response:
    result = json.load(response)
assert result['pii_removed'] is True, result
assert '<EMAIL_ADDRESS>' in result['sanitized_context'], result
print('normal retrieval: redacted, HTTP 200')
PY

docker stop "$PRESIDIO" >/dev/null
docker exec -i "$NEMO" python - <<'PY'
import json
import urllib.error
import urllib.request

request = urllib.request.Request(
    'http://127.0.0.1:8013/api/labs/retrieval',
    data=json.dumps({'chunks': ['Contact alice@example.com for help.']}).encode(),
    headers={'Content-Type': 'application/json'},
)
try:
    urllib.request.urlopen(request, timeout=120)
except urllib.error.HTTPError as error:
    assert error.code >= 500, error.code
    print(f'Presidio unavailable: HTTP {error.code}, no success response')
else:
    raise AssertionError('Presidio failure returned a successful response')
PY
