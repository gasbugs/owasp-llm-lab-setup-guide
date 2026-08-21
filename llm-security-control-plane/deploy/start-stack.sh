#!/usr/bin/env bash
set -euo pipefail

PRESIDIO_INTERNAL_TOKEN="${PRESIDIO_INTERNAL_TOKEN:-control-plane-nemo-to-presidio}"
APPLICATION_INTERNAL_TOKEN="${APPLICATION_INTERNAL_TOKEN:-control-plane-app-to-nemo}"
GUARD_MODE="${GUARD_MODE:-enforce}"
ASSURANCE_PROFILE="${ASSURANCE_PROFILE:-high-assurance}"
ENABLE_LAB_ENDPOINTS="${ENABLE_LAB_ENDPOINTS:-true}"

podman run -d --replace --name llm-security-presidio-spoke \
  --network slirp4netns:allow_host_loopback=true \
  -p 127.0.0.1:18093:8013 \
  -e "PRESIDIO_INTERNAL_TOKEN=$PRESIDIO_INTERNAL_TOKEN" \
  localhost/llm-security-presidio-privacy-spoke:1.0.0 >/dev/null

podman run -d --replace --name llm-security-nemo-hub \
  --network slirp4netns:allow_host_loopback=true \
  -p 127.0.0.1:18094:8014 \
  -e "PRESIDIO_INTERNAL_TOKEN=$PRESIDIO_INTERNAL_TOKEN" \
  -e "APPLICATION_INTERNAL_TOKEN=$APPLICATION_INTERNAL_TOKEN" \
  -e "GUARD_MODE=$GUARD_MODE" \
  -e "ASSURANCE_PROFILE=$ASSURANCE_PROFILE" \
  -e "ENABLE_LAB_ENDPOINTS=$ENABLE_LAB_ENDPOINTS" \
  -e PRESIDIO_URL=http://10.0.2.2:18093 \
  -e OLLAMA_URL=http://10.0.2.2:11434 \
  localhost/llm-security-nemo-policy-hub:1.0.0 >/dev/null

podman run -d --replace --name llm-security-application-gateway \
  --network slirp4netns:allow_host_loopback=true \
  -p 127.0.0.1:18095:8000 \
  -e "APPLICATION_INTERNAL_TOKEN=$APPLICATION_INTERNAL_TOKEN" \
  -e NEMO_HUB_URL=http://10.0.2.2:18094 \
  localhost/llm-security-application-gateway:1.0.0 >/dev/null

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

printf 'control-plane=READY app=http://127.0.0.1:18095 profile=%s mode=%s\n' \
  "$ASSURANCE_PROFILE" "$GUARD_MODE"
