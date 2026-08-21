#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE_VERSION="${BASELINE_VERSION:-1.0.0}"
CANDIDATE_VERSION="${CANDIDATE_VERSION:-1.1.0-candidate}"

for image in application-gateway nemo-policy-hub presidio-privacy-spoke; do
  podman image exists "localhost/llm-security-$image:$BASELINE_VERSION"
  podman tag \
    "localhost/llm-security-$image:$BASELINE_VERSION" \
    "localhost/llm-security-$image:$CANDIDATE_VERSION"
done

IMAGE_VERSION="$CANDIDATE_VERSION" bash "$ROOT/deploy/start-stack.sh" >/dev/null
curl -fsS http://127.0.0.1:18095/healthz | jq '{candidate_version:.version,ok}'

IMAGE_VERSION="$BASELINE_VERSION" bash "$ROOT/deploy/start-stack.sh" >/dev/null
curl -fsS http://127.0.0.1:18095/healthz | jq '{rollback_version:.version,ok}'
