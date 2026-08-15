#!/usr/bin/env bash
# Publisher-only lifecycle check: same-container restart keeps an edit, while
# container recreation restores the vulnerable source baked into the image.
set -euo pipefail

CONTAINER_ENGINE="${CONTAINER_ENGINE:-podman}"
IMAGE="${SECURE_CODING_RAG_IMAGE:-localhost/secure-coding-rag:latest}"
CONTAINER=secure-coding-layer-reset
SOURCE=/app/app/secure_coding.py

cleanup() {
  "$CONTAINER_ENGINE" rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

start_container() {
  "$CONTAINER_ENGINE" run -d --name "$CONTAINER" \
    --entrypoint sh "$IMAGE" -c 'sleep 300' >/dev/null
}

assert_vulnerable() {
  "$CONTAINER_ENGINE" exec "$CONTAINER" grep -q \
    '^[[:space:]]*return allow_untrusted_llm01_input(message).*VULNERABLE-ACTIVE' \
    "$SOURCE"
  "$CONTAINER_ENGINE" exec "$CONTAINER" grep -q \
    '^[[:space:]]*# return enforce_llm01_input_policy(message).*SAFE-ENABLE' \
    "$SOURCE"
}

start_container

mounts=$("$CONTAINER_ENGINE" inspect --format \
  '{{range .Mounts}}{{println .Destination}}{{end}}' "$CONTAINER")
if printf '%s\n' "$mounts" | grep -qx '/app/app'; then
  echo 'container-layer-reset=FAIL reason=unexpected-app-source-mount' >&2
  exit 1
fi

assert_vulnerable
"$CONTAINER_ENGINE" exec "$CONTAINER" sed -i \
  -e 's/^    return allow_untrusted_llm01_input(message)  # VULNERABLE-ACTIVE$/    # return allow_untrusted_llm01_input(message)  # VULNERABLE-ACTIVE/' \
  -e 's/^    # return enforce_llm01_input_policy(message)  # SAFE-ENABLE$/    return enforce_llm01_input_policy(message)  # SAFE-ENABLE/' \
  "$SOURCE"

"$CONTAINER_ENGINE" restart "$CONTAINER" >/dev/null
"$CONTAINER_ENGINE" exec "$CONTAINER" grep -q \
  '^[[:space:]]*return enforce_llm01_input_policy(message).*SAFE-ENABLE' \
  "$SOURCE"
echo 'container-layer-restart=PASS mode=safe'

"$CONTAINER_ENGINE" rm -f "$CONTAINER" >/dev/null
start_container
assert_vulnerable
echo 'container-layer-recreation=PASS mode=vulnerable'
