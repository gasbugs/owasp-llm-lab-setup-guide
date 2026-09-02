#!/usr/bin/env bash
# Publisher-only lifecycle check: same-container restart keeps an edit, while
# container recreation restores the vulnerable source baked into the image.
set -euo pipefail

CONTAINER_ENGINE="${CONTAINER_ENGINE:-docker}"
IMAGE="${SECURE_CODING_RAG_IMAGE:-localhost/secure-coding-rag:latest}"
CONTAINER=secure-coding-layer-reset
SOURCE=/app/app/secure_coding.py

cleanup() {
  "$CONTAINER_ENGINE" rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

start_container() {
  "$CONTAINER_ENGINE" run -d --name "$CONTAINER" \
    --restart=always \
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

restart_policy=$(
  "$CONTAINER_ENGINE" inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$CONTAINER"
)
if [ "$restart_policy" != always ]; then
  echo "container-layer-reset=FAIL reason=restart-policy-$restart_policy" >&2
  exit 1
fi

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

container_id_before=$(
  "$CONTAINER_ENGINE" inspect --format '{{.Id}}' "$CONTAINER"
)
"$CONTAINER_ENGINE" restart "$CONTAINER" >/dev/null
container_id_after=$(
  "$CONTAINER_ENGINE" inspect --format '{{.Id}}' "$CONTAINER"
)
if [ "$container_id_before" != "$container_id_after" ]; then
  echo 'container-layer-reset=FAIL reason=restart-replaced-container' >&2
  exit 1
fi
"$CONTAINER_ENGINE" exec "$CONTAINER" grep -q \
  '^[[:space:]]*return enforce_llm01_input_policy(message).*SAFE-ENABLE' \
  "$SOURCE"
echo 'container-layer-restart=PASS mode=safe same_id=yes restart_policy=always'

"$CONTAINER_ENGINE" rm -f "$CONTAINER" >/dev/null
start_container
assert_vulnerable
echo 'container-layer-recreation=PASS mode=vulnerable'
