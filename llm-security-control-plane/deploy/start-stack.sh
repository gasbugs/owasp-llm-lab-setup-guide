#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_ENV_FILE="${MODULE08_COMPOSE_ENV_FILE:-$ROOT/.state/module08-compose.env}"
if [ -f "$COMPOSE_ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$COMPOSE_ENV_FILE"
  set +a
fi
if [ -n "${POLICY_WORKSPACE:-}" ]; then
  APPLICATION_POLICY_FILE="$POLICY_WORKSPACE/application-policy.yaml"
  CONTROL_PLANE_POLICY_FILE="$POLICY_WORKSPACE/control-plane-policy.yaml"
  PRESIDIO_POLICY_FILE="$POLICY_WORKSPACE/presidio-policy.py"
else
  APPLICATION_POLICY_FILE="$ROOT/policies/application-policy.yaml"
  CONTROL_PLANE_POLICY_FILE="$ROOT/policies/control-plane-policy.yaml"
  PRESIDIO_POLICY_FILE="$ROOT/spokes/presidio-privacy/policy.py"
fi

: "${PRESIDIO_INTERNAL_TOKEN:?Run prepare-module08-runtime.sh to create module08-compose.env}"
: "${APPLICATION_INTERNAL_TOKEN:?Run prepare-module08-runtime.sh to create module08-compose.env}"
: "${BEDROCK_GATEWAY_TOKEN:?Run prepare-module08-runtime.sh to create module08-compose.env}"
: "${AUTH_ADMIN_TOKEN:?Run prepare-module08-runtime.sh to create module08-compose.env}"
GUARD_MODE="${GUARD_MODE:-enforce}"
ASSURANCE_PROFILE="${ASSURANCE_PROFILE:-high-assurance}"
ENABLE_LAB_ENDPOINTS="${ENABLE_LAB_ENDPOINTS:-true}"
IMAGE_VERSION="${IMAGE_VERSION:-1.0.0}"
TELEMETRY_INGEST_TOKEN="${TELEMETRY_INGEST_TOKEN:-}"
AUTH_EVENT_SINK="${AUTH_EVENT_SINK:-}"
LEGACY_STATIC_TOKEN_MODE="${LEGACY_STATIC_TOKEN_MODE:-false}"
AUTH_STATE_DIR="${AUTH_STATE_DIR:-$ROOT/.state/application-auth}"
install -d -m 0700 "$AUTH_STATE_DIR"

NETWORK_NAME=llm-security-control-plane
if podman network exists llm-security-observability; then
  NETWORK_NAME=llm-security-observability
elif ! podman network exists "$NETWORK_NAME"; then
  podman network create "$NETWORK_NAME" >/dev/null
fi
NETWORK_ARGS=(--network "$NETWORK_NAME")
PRESIDIO_URL=http://llm-security-presidio-spoke:8013
NEMO_HUB_URL=http://llm-security-nemo-hub:8014
MODEL_GATEWAY_URL="${MODEL_GATEWAY_URL:-http://llm-security-bedrock-gateway:8080}"
START_BEDROCK_GATEWAY="${START_BEDROCK_GATEWAY:-true}"
OTEL_ARGS=(--network "$NETWORK_NAME")
BEDROCK_MODEL_ID="${BEDROCK_MODEL_ID:-us.amazon.nova-lite-v1:0}"
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
AWS_PROFILE="${AWS_PROFILE:-owasp-llm}"
AWS_CONFIG_DIR="${AWS_CONFIG_DIR:-$HOME/.aws}"
MODULE08_STATE_FILE="${MODULE08_STATE_FILE:-$ROOT/.state/module08-aws.env}"
if [ -f "$MODULE08_STATE_FILE" ]; then
  # shellcheck disable=SC1090
  source "$MODULE08_STATE_FILE"
fi
if [ "$START_BEDROCK_GATEWAY" = true ] && [ ! -d "$AWS_CONFIG_DIR" ]; then
  echo "AWS config directory does not exist: $AWS_CONFIG_DIR" >&2
  exit 1
fi
if podman container exists llm-sec-alloy && podman container exists llm-sec-gateway; then
  OTEL_ARGS+=(
    -e SECURITY_MONITOR_URL=http://llm-sec-gateway:8080
    -e "TELEMETRY_INGEST_TOKEN=$TELEMETRY_INGEST_TOKEN"
    -e OTEL_EXPORTER_OTLP_ENDPOINT=http://llm-sec-alloy:4318
  )
  AUTH_EVENT_SINK="${AUTH_EVENT_SINK:-stdout,monitor}"
fi
AUTH_EVENT_SINK="${AUTH_EVENT_SINK:-stdout}"

if [ "$START_BEDROCK_GATEWAY" = true ]; then
  podman run -d --replace --name llm-security-bedrock-gateway \
    --userns=keep-id:uid=65532,gid=65532 \
    -p 127.0.0.1:18096:8080 \
    -e "AWS_REGION=$AWS_REGION" \
    -e "AWS_PROFILE=$AWS_PROFILE" \
    -e AWS_SHARED_CREDENTIALS_FILE=/tmp/.aws/credentials \
    -e AWS_CONFIG_FILE=/tmp/.aws/config \
    -e "BEDROCK_MODEL_ID=$BEDROCK_MODEL_ID" \
    -e "BEDROCK_GATEWAY_TOKEN=$BEDROCK_GATEWAY_TOKEN" \
    -e "BEDROCK_KNOWLEDGE_BASE_ID=${MODULE08_KNOWLEDGE_BASE_ID:-}" \
    -e "BEDROCK_INPUT_USD_PER_MILLION=${BEDROCK_INPUT_USD_PER_MILLION:-0.06}" \
    -e "BEDROCK_OUTPUT_USD_PER_MILLION=${BEDROCK_OUTPUT_USD_PER_MILLION:-0.24}" \
    -e "BEDROCK_PRICING_REFERENCE_DATE=${BEDROCK_PRICING_REFERENCE_DATE:-2026-08-24}" \
    -e "RELEASE_VERSION=$IMAGE_VERSION" \
    "${OTEL_ARGS[@]}" \
    -v "$AWS_CONFIG_DIR:/tmp/.aws:ro" \
    "localhost/llm-security-bedrock-gateway:$IMAGE_VERSION" >/dev/null
fi

podman run -d --replace --name llm-security-presidio-spoke \
  -p 127.0.0.1:18093:8013 \
  -e "PRESIDIO_INTERNAL_TOKEN=$PRESIDIO_INTERNAL_TOKEN" \
  -e "RELEASE_VERSION=$IMAGE_VERSION" \
  "${OTEL_ARGS[@]}" \
  -v "$PRESIDIO_POLICY_FILE:/app/policy.py:ro,Z" \
  "localhost/llm-security-presidio-privacy-spoke:$IMAGE_VERSION" >/dev/null

podman run -d --replace --name llm-security-nemo-hub \
  -p 127.0.0.1:18094:8014 \
  -e "PRESIDIO_INTERNAL_TOKEN=$PRESIDIO_INTERNAL_TOKEN" \
  -e "APPLICATION_INTERNAL_TOKEN=$APPLICATION_INTERNAL_TOKEN" \
  -e "GUARD_MODE=$GUARD_MODE" \
  -e "ASSURANCE_PROFILE=$ASSURANCE_PROFILE" \
  -e "ENABLE_LAB_ENDPOINTS=$ENABLE_LAB_ENDPOINTS" \
  -e "RELEASE_VERSION=$IMAGE_VERSION" \
  "${OTEL_ARGS[@]}" \
  -e "PRESIDIO_URL=$PRESIDIO_URL" \
  -e "MODEL_GATEWAY_URL=$MODEL_GATEWAY_URL" \
  -e "BEDROCK_MODEL_ID=$BEDROCK_MODEL_ID" \
  -e "BEDROCK_GATEWAY_TOKEN=$BEDROCK_GATEWAY_TOKEN" \
  -v "$CONTROL_PLANE_POLICY_FILE:/app/policies/control-plane-policy.yaml:ro,Z" \
  -v "$ROOT/nemo-policy-hub/config:/app/nemo-config:ro,Z" \
  -v "$ROOT/nemo-policy-hub/hub_core.py:/app/hub_core.py:ro,Z" \
  "localhost/llm-security-nemo-policy-hub:$IMAGE_VERSION" >/dev/null

podman run -d --replace --name llm-security-application-gateway \
  --userns=keep-id:uid=65532,gid=65532 \
  -p 127.0.0.1:18095:8000 \
  -e "APPLICATION_INTERNAL_TOKEN=$APPLICATION_INTERNAL_TOKEN" \
  -e "RELEASE_VERSION=$IMAGE_VERSION" \
  -e "NEMO_HUB_URL=$NEMO_HUB_URL" \
  -e "MODEL_GATEWAY_URL=$MODEL_GATEWAY_URL" \
  -e "BEDROCK_GATEWAY_TOKEN=$BEDROCK_GATEWAY_TOKEN" \
  -e "AUTH_EVENT_SINK=$AUTH_EVENT_SINK" \
  -e "AUTH_ADMIN_TOKEN=$AUTH_ADMIN_TOKEN" \
  -e "LEGACY_STATIC_TOKEN_MODE=$LEGACY_STATIC_TOKEN_MODE" \
  "${OTEL_ARGS[@]}" \
  -v "$APPLICATION_POLICY_FILE:/app/policies/application-policy.yaml:ro,Z" \
  -v "$ROOT/policies/application-users.yaml:/app/policies/application-users.yaml:ro,Z" \
  -v "$AUTH_STATE_DIR:/app/state:rw,Z" \
  -v "$ROOT/application-gateway/auth.py:/app/auth.py:ro,Z" \
  -v "$ROOT/application-gateway/policy.py:/app/policy.py:ro,Z" \
  -v "$ROOT/application-gateway/server.py:/app/server.py:ro,Z" \
  "localhost/llm-security-application-gateway:$IMAGE_VERSION" >/dev/null

HEALTH_URLS=(
  http://127.0.0.1:18093/healthz
  http://127.0.0.1:18094/healthz
  http://127.0.0.1:18095/healthz
)
if [ "$START_BEDROCK_GATEWAY" = true ]; then
  HEALTH_URLS=(http://127.0.0.1:18096/healthz "${HEALTH_URLS[@]}")
fi
for url in "${HEALTH_URLS[@]}"; do
  ready=false
  for _ in $(seq 1 90); do
    if curl -fsS --max-time 3 "$url" 2>/dev/null | jq -e '.ok == true' >/dev/null 2>&1; then
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

printf 'control-plane=READY app=http://127.0.0.1:18095 model=%s profile=%s mode=%s version=%s\n' \
  "$BEDROCK_MODEL_ID" "$ASSURANCE_PROFILE" "$GUARD_MODE" "$IMAGE_VERSION"
