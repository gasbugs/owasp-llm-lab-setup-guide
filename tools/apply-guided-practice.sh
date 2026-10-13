#!/usr/bin/env bash
set -Eeuo pipefail

[[ $# -eq 1 ]] || { printf '사용법: %s P01-01\n' "$0" >&2; exit 2; }
MISSION_ID="$1"
SETUP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$SETUP_ROOT/tools/guided-practice-files.tsv"
COMPOSE_FILE="$SETUP_ROOT/examples/security-monitoring/compose.guided.yaml"
ENV_FILE="$SETUP_ROOT/llm-security-control-plane/.state/guided-course.env"

mapfile -t rows < <(awk -F'|' -v id="$MISSION_ID" '$1 == id {print}' "$MANIFEST")
(( ${#rows[@]} > 0 )) || { printf '알 수 없는 미션 번호입니다: %s\n' "$MISSION_ID" >&2; exit 2; }

"$SETUP_ROOT/tools/initialize-guided-practice.sh" >/dev/null
override_file="$("$SETUP_ROOT/tools/prepare-guided-practice-build.sh")"
services=()
for row in "${rows[@]}"; do
  IFS='|' read -r display_id source_path workspace_name service_list <<< "$row"
  IFS=',' read -ra row_services <<< "$service_list"
  services+=("${row_services[@]}")
done
mapfile -t services < <(printf '%s\n' "${services[@]}" | sort -u)

docker compose --env-file "$ENV_FILE" --file "$COMPOSE_FILE" --file "$override_file" build "${services[@]}"
docker compose --env-file "$ENV_FILE" --file "$COMPOSE_FILE" --file "$override_file" up -d --no-deps --force-recreate "${services[@]}"
printf '%s 작업 파일을 적용했습니다. setup의 Starter 파일은 변경하지 않았습니다.\n' "$MISSION_ID"
