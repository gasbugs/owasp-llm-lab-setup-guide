#!/usr/bin/env bash
# Recreate the chapter 02-04 evaluation stack with fresh local credentials.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KNOWLEDGE_BASE_ID=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --knowledge-base-id)
      [ "$#" -ge 2 ] || { echo 'Missing Knowledge Base ID' >&2; exit 2; }
      KNOWLEDGE_BASE_ID="$2"
      [[ "$KNOWLEDGE_BASE_ID" =~ ^[A-Za-z0-9]{10}$ ]] || { echo 'Invalid Knowledge Base ID' >&2; exit 2; }
      shift 2 ;;
    --help)
      echo 'Usage: bash prepare-evaluation-environment.sh [--knowledge-base-id ID]'
      echo 'Builds four services, removes the six named lab containers, backs up .state, and creates fresh tokens.'
      echo 'Keeps ~/.aws and learner work files; ensures the lab Knowledge Base when no ID is supplied.'
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

for tool in docker aws openssl curl jq; do
  command -v "$tool" >/dev/null || { echo "Required command missing: $tool" >&2; exit 1; }
done
docker info >/dev/null
docker compose version >/dev/null
[ -d "$HOME/.aws" ] || { echo 'AWS configuration directory missing: ~/.aws' >&2; exit 1; }
AWS_SHARED_CREDENTIALS_FILE="$HOME/.aws/credentials" AWS_CONFIG_FILE="$HOME/.aws/config" \
  aws sts get-caller-identity --profile default --region us-east-1 >/dev/null

# Build first so a build failure does not destroy the previous runtime or state.
# This temporary directory also lives under the Git-ignored setup .state.
mkdir -p "$ROOT/../.state"
PREPARATION_DIR="$(mktemp -d "$ROOT/../.state/evaluation-preparation-XXXXXXXX")"
trap 'rm -rf "$PREPARATION_DIR"' EXIT
ENV_FILE="$PREPARATION_DIR/module08-compose.env"
(
  umask 077
  cat > "$ENV_FILE" <<ENV
AWS_PROFILE=default
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0
MODULE08_KNOWLEDGE_BASE_ID=$KNOWLEDGE_BASE_ID
PRESIDIO_INTERNAL_TOKEN=$(openssl rand -hex 24)
APPLICATION_INTERNAL_TOKEN=$(openssl rand -hex 24)
BEDROCK_GATEWAY_TOKEN=$(openssl rand -hex 24)
TELEMETRY_INGEST_TOKEN=$(openssl rand -hex 24)
TELEMETRY_HMAC_KEY=$(openssl rand -hex 32)
LLM_MONITOR_TOKEN=$(openssl rand -hex 24)
LLM_MONITOR_ADMIN_TOKEN=$(openssl rand -hex 24)
RETRIEVAL_SERVICE_TOKEN=$(openssl rand -hex 24)
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=$(openssl rand -hex 18)
AUTH_ADMIN_TOKEN=$(openssl rand -hex 24)
GUARD_MODE=enforce
ASSURANCE_PROFILE=high-assurance
LEGACY_STATIC_TOKEN_MODE=false
CONTROL_PLANE_POLICY_SOURCE=$ROOT/policies/evaluation-control-plane-policy.yaml
NEMO_CONFIG_SOURCE=$ROOT/nemo-policy-hub/config
ENABLE_LAB_ENDPOINTS=true
IMAGE_VERSION=1.0.0
LOCAL_UID=$(id -u)
LOCAL_GID=$(id -g)
BEDROCK_HOST_PORT=18096
PRESIDIO_HOST_PORT=18093
HUB_HOST_PORT=18094
APPLICATION_HOST_PORT=18095
CONTROL_PLANE_NETWORK_NAME=llm-security-control-plane
ENV
)
# Load generated values literally; never execute an old learner environment file.
while IFS='=' read -r name value; do
  export "$name=$value"
done < "$ENV_FILE"
export AWS_CREDENTIALS_DIR="$HOME/.aws"
export PRESIDIO_POLICY_SOURCE="$ROOT/spokes/presidio-privacy/policy.py"
export APPLICATION_POLICY_SOURCE="$ROOT/policies/application-policy.yaml"
export AUTH_EVENT_SINK=stdout SECURITY_MONITOR_URL= OTEL_EXPORTER_OTLP_ENDPOINT=
compose() {
  docker compose --project-name llm-security-control-plane \
    --env-file "$ENV_FILE" -f "$ROOT/compose.yaml" "$@"
}
compose config --quiet
compose build bedrock-gateway presidio nemo-hub application

# Resolve AWS resources before removing the previous containers or local state.
export AWS_PROFILE=default AWS_REGION=us-east-1
export AWS_SHARED_CREDENTIALS_FILE="$HOME/.aws/credentials" AWS_CONFIG_FILE="$HOME/.aws/config"
if [ -z "$KNOWLEDGE_BASE_ID" ]; then
  MODULE08_AWS_STATE_DIR="$PREPARATION_DIR/aws" \
    bash "$ROOT/deploy/restore-module08-aws.sh" --ensure
  KNOWLEDGE_BASE_ID="$(sed -n 's/^MODULE08_KNOWLEDGE_BASE_ID=//p' "$PREPARATION_DIR/aws/module08-aws.env")"
else
  status="$(aws bedrock-agent get-knowledge-base --region us-east-1 \
    --knowledge-base-id "$KNOWLEDGE_BASE_ID" --query 'knowledgeBase.status' --output text)"
  [ "$status" = ACTIVE ] || { echo "Knowledge Base is not ACTIVE: $status" >&2; exit 1; }
fi
[[ "$KNOWLEDGE_BASE_ID" =~ ^[A-Za-z0-9]{10}$ ]] || { echo 'Knowledge Base resolution failed' >&2; exit 1; }
sed -i "s/^MODULE08_KNOWLEDGE_BASE_ID=.*/MODULE08_KNOWLEDGE_BASE_ID=$KNOWLEDGE_BASE_ID/" "$ENV_FILE"
export MODULE08_KNOWLEDGE_BASE_ID="$KNOWLEDGE_BASE_ID"
printf 'evaluation-knowledge-base=%s region=us-east-1\n' "$KNOWLEDGE_BASE_ID"

# Only explicitly named chapter containers can be removed; Docker errors propagate.
for container in llm-security-application-gateway llm-security-nemo-hub \
  llm-security-presidio-spoke llm-security-bedrock-gateway \
  llm-security-nemo-dialog-rails guardrails-presidio-api; do
  found="$(docker ps -aq --filter "name=^/${container}$")"
  if [ -n "$found" ]; then
    docker rm -f "$container" >/dev/null
  fi
done

if [ -e "$ROOT/.state" ]; then
  BACKUP_DIR="$ROOT/../.state/control-plane-backup-$(date +%Y%m%d-%H%M%S-%N)"
  mv "$ROOT/.state" "$BACKUP_DIR"
  printf 'previous-state-backup=%s\n' "$BACKUP_DIR"
fi
mkdir -p "$ROOT/.state/application-auth"
mv "$ENV_FILE" "$ROOT/.state/module08-compose.env"
ENV_FILE="$ROOT/.state/module08-compose.env"
if [ -f "$PREPARATION_DIR/aws/module08-aws.env" ]; then
  cp "$PREPARATION_DIR/aws/module08-aws.env" "$ROOT/.state/module08-aws.env"
fi
compose up -d --force-recreate --wait --wait-timeout 180 \
  bedrock-gateway presidio nemo-hub application
compose ps -a
for url in http://127.0.0.1:18096/healthz http://127.0.0.1:18093/healthz \
  http://127.0.0.1:18094/healthz http://127.0.0.1:18095/healthz; do
  curl -fsS --max-time 10 "$url" | jq -e '.ok == true' >/dev/null
done
curl -fsS --max-time 10 http://127.0.0.1:18094/api/guardrails/policy \
  | jq -e '.guard_mode == "enforce" and .assurance_profile == "high-assurance" and
           .presidio_failure_mode == "closed" and .main_task.id == "account-security-support-v1"' >/dev/null
printf 'evaluation-environment=READY app=http://127.0.0.1:18095 mode=enforce profile=high-assurance auth=jwt presidio-failure=closed\n'
