#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE="${1:-$HOME/work/llm-security-control-plane-policy}"

mkdir -p "$WORKSPACE"
cp "$ROOT/policies/application-policy.yaml" "$WORKSPACE/application-policy.yaml"
cp "$ROOT/policies/nemo-policy.yaml" "$WORKSPACE/nemo-policy.yaml"
cp "$ROOT/spokes/presidio-privacy/policy.py" "$WORKSPACE/presidio-policy.py"

printf 'policy-workspace=%s files=3\n' "$WORKSPACE"
