#!/usr/bin/env bash

write_module08_compose_env() {
  local state_dir=$1
  local compose_env_file=$2
  local current_knowledge_base_id=${3:-}
  local aws_profile=${AWS_PROFILE:-default}
  local aws_region=${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}
  local presidio_token application_token bedrock_token telemetry_token telemetry_hmac
  local monitor_token monitor_admin_token retrieval_token grafana_password auth_admin_token

  install -d -m 0700 "$state_dir"
  umask 077

  read_existing_or_generate() {
    local key=$1
    local bytes=$2
    local existing=""
    if [ -f "$compose_env_file" ]; then
      existing="$(sed -n "s/^${key}=//p" "$compose_env_file" | head -n 1)"
    fi
    if [ -n "$existing" ]; then
      printf '%s' "$existing"
    else
      openssl rand -hex "$bytes"
    fi
  }

  presidio_token="$(read_existing_or_generate PRESIDIO_INTERNAL_TOKEN 24)"
  application_token="$(read_existing_or_generate APPLICATION_INTERNAL_TOKEN 24)"
  bedrock_token="$(read_existing_or_generate BEDROCK_GATEWAY_TOKEN 24)"
  telemetry_token="$(read_existing_or_generate TELEMETRY_INGEST_TOKEN 24)"
  telemetry_hmac="$(read_existing_or_generate TELEMETRY_HMAC_KEY 32)"
  monitor_token="$(read_existing_or_generate LLM_MONITOR_TOKEN 24)"
  monitor_admin_token="$(read_existing_or_generate LLM_MONITOR_ADMIN_TOKEN 24)"
  retrieval_token="$(read_existing_or_generate RETRIEVAL_SERVICE_TOKEN 24)"
  grafana_password="$(read_existing_or_generate GRAFANA_ADMIN_PASSWORD 18)"
  auth_admin_token="$(read_existing_or_generate AUTH_ADMIN_TOKEN 24)"

  {
    printf 'AWS_PROFILE=%s\n' "$aws_profile"
    printf 'AWS_REGION=%s\n' "$aws_region"
    printf 'BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0\n'
    printf 'MODULE08_KNOWLEDGE_BASE_ID=%s\n' "$current_knowledge_base_id"
    printf 'PRESIDIO_INTERNAL_TOKEN=%s\n' "$presidio_token"
    printf 'APPLICATION_INTERNAL_TOKEN=%s\n' "$application_token"
    printf 'BEDROCK_GATEWAY_TOKEN=%s\n' "$bedrock_token"
    printf 'TELEMETRY_INGEST_TOKEN=%s\n' "$telemetry_token"
    printf 'TELEMETRY_HMAC_KEY=%s\n' "$telemetry_hmac"
    printf 'LLM_MONITOR_TOKEN=%s\n' "$monitor_token"
    printf 'LLM_MONITOR_ADMIN_TOKEN=%s\n' "$monitor_admin_token"
    printf 'RETRIEVAL_SERVICE_TOKEN=%s\n' "$retrieval_token"
    printf 'GRAFANA_ADMIN_USER=admin\n'
    printf 'GRAFANA_ADMIN_PASSWORD=%s\n' "$grafana_password"
    printf 'AUTH_ADMIN_TOKEN=%s\n' "$auth_admin_token"
    printf 'GUARD_MODE=enforce\n'
    printf 'ASSURANCE_PROFILE=high-assurance\n'
    printf 'ENABLE_LAB_ENDPOINTS=true\n'
    printf 'IMAGE_VERSION=1.0.0\n'
    printf 'DIALOG_IMAGE_VERSION=0.22.0\n'
  } > "$compose_env_file"
  chmod 0600 "$compose_env_file"
}
