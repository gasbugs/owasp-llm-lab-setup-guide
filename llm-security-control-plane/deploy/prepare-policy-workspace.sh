#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE="${1:-$HOME/work/llm-security-control-plane-policy}"

mkdir -p "$WORKSPACE"
chmod 0755 "$WORKSPACE"
cp "$ROOT/policies/application-policy.yaml" "$WORKSPACE/application-policy.yaml"
cp "$ROOT/policies/control-plane-policy.yaml" "$WORKSPACE/control-plane-policy.yaml"
cp "$ROOT/spokes/presidio-privacy/policy.py" "$WORKSPACE/presidio-policy.py"
mkdir -p "$WORKSPACE/nemo-config"
cp -R "$ROOT/nemo-policy-hub/config/." "$WORKSPACE/nemo-config/"
find "$WORKSPACE/nemo-config" -type d -exec chmod 0755 {} +
find "$WORKSPACE/nemo-config" -type f -exec chmod 0644 {} +
chmod 0644 "$WORKSPACE/application-policy.yaml" \
  "$WORKSPACE/control-plane-policy.yaml" "$WORKSPACE/presidio-policy.py"

printf 'policy-workspace=%s policies=3 nemo-config=ready\n' "$WORKSPACE"
