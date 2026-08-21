#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

podman build \
  -f "$ROOT/spokes/presidio-privacy/Containerfile" \
  -t localhost/llm-security-presidio-privacy-spoke:1.0.0 \
  "$ROOT"

podman build \
  -f "$ROOT/nemo-policy-hub/Containerfile" \
  -t localhost/llm-security-nemo-policy-hub:1.0.0 \
  "$ROOT"

podman build \
  -f "$ROOT/application-gateway/Containerfile" \
  -t localhost/llm-security-application-gateway:1.0.0 \
  "$ROOT"
