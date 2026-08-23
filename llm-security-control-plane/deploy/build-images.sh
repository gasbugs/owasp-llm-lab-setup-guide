#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_VERSION="${IMAGE_VERSION:-1.0.0}"

podman build \
  -f "$ROOT/bedrock-gateway/Containerfile" \
  -t "localhost/llm-security-bedrock-gateway:$IMAGE_VERSION" \
  "$ROOT"

podman build \
  -f "$ROOT/spokes/presidio-privacy/Containerfile" \
  -t "localhost/llm-security-presidio-privacy-spoke:$IMAGE_VERSION" \
  "$ROOT"

podman build \
  -f "$ROOT/nemo-policy-hub/Containerfile" \
  -t "localhost/llm-security-nemo-policy-hub:$IMAGE_VERSION" \
  "$ROOT"

podman build \
  -f "$ROOT/application-gateway/Containerfile" \
  -t "localhost/llm-security-application-gateway:$IMAGE_VERSION" \
  "$ROOT"
