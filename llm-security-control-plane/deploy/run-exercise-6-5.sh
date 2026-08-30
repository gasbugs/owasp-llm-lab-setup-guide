#!/usr/bin/env bash
set -euo pipefail

# Chapter 08, exercise 6.5: build every learner-facing image from this
# checkout, then run the progressive control-plane exercise without AWS.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
MODE=run

case "${1:-}" in
  "") ;;
  --build-only) MODE=build-only ;;
  *) echo "usage: $0 [--build-only]" >&2; exit 2 ;;
esac

pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

for command in podman curl jq ss; do
  command -v "$command" >/dev/null 2>&1 \
    || fail "required command missing: $command"
done
podman info >/dev/null 2>&1 || fail "Podman is not ready for the current user"

for path in \
  "$ROOT/versions.lock.yaml" \
  "$ROOT/deploy/build-images.sh" \
  "$ROOT/tests/e2e-learning-sequence.sh" \
  "$REPO_ROOT/examples/day6/nemo-guardrails/Containerfile" \
  "$REPO_ROOT/examples/day6/presidio/Containerfile"; do
  test -f "$path" || fail "source file missing: $path"
done

pass "preflight complete"
printf '[BUILD] four Chapter 08 control-plane images\n'
bash "$ROOT/deploy/build-images.sh"

printf '[BUILD] NeMo dialog rail used by the progressive exercise\n'
podman build \
  --tag localhost/llm-security-nemo-dialog-rails:0.22.0 \
  "$REPO_ROOT/examples/day6/nemo-guardrails"

printf '[BUILD] Presidio service used by the progressive exercise\n'
podman build \
  --tag localhost/day6-presidio:2.2.362 \
  "$REPO_ROOT/examples/day6/presidio"

for image in \
  localhost/llm-security-bedrock-gateway:1.0.0 \
  localhost/llm-security-presidio-privacy-spoke:1.0.0 \
  localhost/llm-security-nemo-policy-hub:1.0.0 \
  localhost/llm-security-application-gateway:1.0.0 \
  localhost/llm-security-nemo-dialog-rails:0.22.0 \
  localhost/day6-presidio:2.2.362; do
  podman image exists "$image" || fail "image was not built: $image"
done
pass "all six images built from the current checkout"

if [ "$MODE" = build-only ]; then
  printf 'module08-exercise-6.5=BUILD_READY\n'
  exit 0
fi

# The learning sequence uses a dedicated network, fixed loopback ports and a
# trap that removes only its own containers/network. Refuse collisions rather
# than replacing another lab owned by the learner.
for port in 28091 28092 28093 28094 28096; do
  if ss -ltn 2>/dev/null | awk -v suffix=":$port" '$4 ~ suffix "$" {found=1} END {exit(found ? 0 : 1)}'; then
    fail "loopback exercise port is already in use: $port"
  fi
done

printf '[RUN] progressive guardrail sequence with deterministic Bedrock\n'
bash "$ROOT/tests/e2e-learning-sequence.sh"
printf 'module08-exercise-6.5=PASS\n'
