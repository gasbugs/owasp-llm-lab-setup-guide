#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -n "${POLICY_WORKSPACE:-}" ]; then
  APPLICATION_POLICY_FILE="$POLICY_WORKSPACE/application-policy.yaml"
  NEMO_POLICY_FILE="$POLICY_WORKSPACE/nemo-policy.yaml"
  PRESIDIO_POLICY_FILE="$POLICY_WORKSPACE/presidio-policy.py"
else
  APPLICATION_POLICY_FILE="$ROOT/policies/application-policy.yaml"
  NEMO_POLICY_FILE="$ROOT/policies/nemo-policy.yaml"
  PRESIDIO_POLICY_FILE="$ROOT/spokes/presidio-privacy/policy.py"
fi

PRESIDIO_INTERNAL_TOKEN="${PRESIDIO_INTERNAL_TOKEN:-control-plane-nemo-to-presidio}"
APPLICATION_INTERNAL_TOKEN="${APPLICATION_INTERNAL_TOKEN:-control-plane-app-to-nemo}"
GUARD_MODE="${GUARD_MODE:-enforce}"
ASSURANCE_PROFILE="${ASSURANCE_PROFILE:-high-assurance}"
ENABLE_LAB_ENDPOINTS="${ENABLE_LAB_ENDPOINTS:-true}"
IMAGE_VERSION="${IMAGE_VERSION:-1.0.0}"
TELEMETRY_INGEST_TOKEN="${TELEMETRY_INGEST_TOKEN:-module08-telemetry-ingest}"

NETWORK_ARGS=(--network slirp4netns:allow_host_loopback=true)
PRESIDIO_URL=http://10.0.2.2:18093
NEMO_HUB_URL=http://10.0.2.2:18094
MONITOR_ARGS=()
OLLAMA_URL=http://10.0.2.2:11434
if podman network exists llm-security-observability; then
  NETWORK_ARGS=(--network llm-security-observability)
  PRESIDIO_URL=http://llm-security-presidio-spoke:8013
  NEMO_HUB_URL=http://llm-security-nemo-hub:8014
  OLLAMA_URL=http://host.containers.internal:11434
  MONITOR_ARGS=(
    -e SECURITY_MONITOR_URL=http://llm-sec-gateway:8080
    -e "TELEMETRY_INGEST_TOKEN=$TELEMETRY_INGEST_TOKEN"
  )
fi

podman run -d --replace --name llm-security-presidio-spoke \
  "${NETWORK_ARGS[@]}" \
  -p 127.0.0.1:18093:8013 \
  -e "PRESIDIO_INTERNAL_TOKEN=$PRESIDIO_INTERNAL_TOKEN" \
  -e "RELEASE_VERSION=$IMAGE_VERSION" \
  -v "$PRESIDIO_POLICY_FILE:/app/policy.py:ro,Z" \
  "localhost/llm-security-presidio-privacy-spoke:$IMAGE_VERSION" >/dev/null

podman run -d --replace --name llm-security-nemo-hub \
  "${NETWORK_ARGS[@]}" \
  -p 127.0.0.1:18094:8014 \
  -e "PRESIDIO_INTERNAL_TOKEN=$PRESIDIO_INTERNAL_TOKEN" \
  -e "APPLICATION_INTERNAL_TOKEN=$APPLICATION_INTERNAL_TOKEN" \
  -e "GUARD_MODE=$GUARD_MODE" \
  -e "ASSURANCE_PROFILE=$ASSURANCE_PROFILE" \
  -e "ENABLE_LAB_ENDPOINTS=$ENABLE_LAB_ENDPOINTS" \
  -e "RELEASE_VERSION=$IMAGE_VERSION" \
  -e "PRESIDIO_URL=$PRESIDIO_URL" \
  --add-host host.containers.internal:host-gateway \
  -e "OLLAMA_URL=$OLLAMA_URL" \
  -v "$NEMO_POLICY_FILE:/app/policies/nemo-policy.yaml:ro,Z" \
  -v "$ROOT/versions.lock.yaml:/app/versions.lock.yaml:ro,Z" \
  -v "$ROOT/nemo-policy-hub/hub_core.py:/app/hub_core.py:ro,Z" \
  "localhost/llm-security-nemo-policy-hub:$IMAGE_VERSION" >/dev/null

podman run -d --replace --name llm-security-application-gateway \
  "${NETWORK_ARGS[@]}" \
  -p 127.0.0.1:18095:8000 \
  -e "APPLICATION_INTERNAL_TOKEN=$APPLICATION_INTERNAL_TOKEN" \
  -e "RELEASE_VERSION=$IMAGE_VERSION" \
  -e "NEMO_HUB_URL=$NEMO_HUB_URL" \
  "${MONITOR_ARGS[@]}" \
  -v "$APPLICATION_POLICY_FILE:/app/policies/application-policy.yaml:ro,Z" \
  -v "$ROOT/application-gateway/policy.py:/app/policy.py:ro,Z" \
  -v "$ROOT/application-gateway/server.py:/app/server.py:ro,Z" \
  "localhost/llm-security-application-gateway:$IMAGE_VERSION" >/dev/null

for url in \
  http://127.0.0.1:18093/healthz \
  http://127.0.0.1:18094/healthz \
  http://127.0.0.1:18095/healthz; do
  ready=false
  for _ in $(seq 1 90); do
    if curl -fsS --max-time 3 "$url" | jq -e '.ok == true' >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 2
  done
  if [ "$ready" != true ]; then
    echo "service did not become ready: $url" >&2
    exit 1
  fi
done

printf 'control-plane=READY app=http://127.0.0.1:18095 profile=%s mode=%s version=%s\n' \
  "$ASSURANCE_PROFILE" "$GUARD_MODE" "$IMAGE_VERSION"
