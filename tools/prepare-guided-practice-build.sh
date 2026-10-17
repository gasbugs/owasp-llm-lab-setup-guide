#!/usr/bin/env bash
set -Eeuo pipefail

SETUP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTROL_ROOT="$SETUP_ROOT/llm-security-control-plane"
MANIFEST="$SETUP_ROOT/tools/guided-practice-files.tsv"
PRACTICE_ROOT="${GUIDED_PRACTICE_DIR:-$HOME/owasp-llm-practice}"
BUILD_ROOT="$SETUP_ROOT/.state/guided-practice-build"
OVERRIDE_FILE="$CONTROL_ROOT/.state/guided-practice-build.override.yaml"

# 빌드된 image의 non-root 사용자가 추적 중인 source를 읽을 수 있어야 합니다.
umask 022
rm -rf "$BUILD_ROOT"
mkdir -p "$BUILD_ROOT" "$(dirname "$OVERRIDE_FILE")"
git -C "$SETUP_ROOT" archive HEAD llm-security-control-plane |
  tar -x --strip-components=1 -C "$BUILD_ROOT"

services=()
while IFS='|' read -r display_id source_path workspace_name service_list; do
  [[ -n "$display_id" && "$display_id" != \#* ]] || continue
  workspace_file="$PRACTICE_ROOT/$workspace_name"
  [[ -f "$workspace_file" ]] || { printf '작업 파일이 없습니다: %s\n' "$workspace_file" >&2; exit 1; }
  install -D -m 0644 "$workspace_file" "$BUILD_ROOT/$source_path"
  IFS=',' read -ra row_services <<< "$service_list"
  services+=("${row_services[@]}")
done < "$MANIFEST"

{
  printf 'services:\n'
  printf '%s\n' "${services[@]}" | sort -u | while IFS= read -r service; do
    printf '  %s:\n    build:\n      context: %s\n' "$service" "$BUILD_ROOT"
  done
} > "$OVERRIDE_FILE"

printf '%s\n' "$OVERRIDE_FILE"
