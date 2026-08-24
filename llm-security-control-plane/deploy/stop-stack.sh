#!/usr/bin/env bash
set -euo pipefail

podman rm -f \
  llm-security-application-gateway \
  llm-security-nemo-hub \
  llm-security-presidio-spoke \
  llm-security-bedrock-gateway
