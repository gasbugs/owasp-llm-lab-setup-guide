#!/usr/bin/env bash
set -Eeuo pipefail

SETUP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$SETUP_ROOT/tools/guided-practice-files.tsv"
PRACTICE_ROOT="${GUIDED_PRACTICE_DIR:-$HOME/owasp-llm-practice}"

mkdir -p "$PRACTICE_ROOT"
while IFS='|' read -r display_id source_path workspace_name services; do
  [[ -n "$display_id" && "$display_id" != \#* ]] || continue
  workspace_file="$PRACTICE_ROOT/$workspace_name"
  git -C "$SETUP_ROOT" cat-file -e "HEAD:llm-security-control-plane/$source_path" || {
    printf '커밋된 Starter 파일이 없습니다: %s\n' "$source_path" >&2
    exit 1
  }
  if [[ ! -e "$workspace_file" ]]; then
    git -C "$SETUP_ROOT" show "HEAD:llm-security-control-plane/$source_path" > "$workspace_file"
    printf 'Starter 복제: %s\n' "$workspace_file"
  fi
done < "$MANIFEST"

printf 'Practice 작업 폴더: %s\n' "$PRACTICE_ROOT"
