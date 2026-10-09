#!/usr/bin/env bash
set -Eeuo pipefail

SETUP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$SETUP_ROOT/examples/security-monitoring/compose.guided.yaml"
STATE_DIR="$SETUP_ROOT/llm-security-control-plane/.state"
ENV_FILE="$STATE_DIR/guided-course.env"

log() { printf '\n[%s] %s\n' "$1" "$2"; }
fail() { printf '\n[오류] %s\n' "$1" >&2; exit 1; }

log "1/5" "필수 프로그램과 AWS 자격 증명을 확인합니다."
for command_name in docker aws openssl python3 grep sort; do
  command -v "$command_name" >/dev/null 2>&1 ||
    fail "$command_name 명령을 찾지 못했습니다. 01 테넌트 환경 준비를 먼저 완료하세요."
done
docker info >/dev/null 2>&1 ||
  fail "Docker daemon에 접근할 수 없습니다. Docker 실행 상태와 docker 그룹 권한을 확인하세요."
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2를 사용할 수 없습니다."
aws sts get-caller-identity --profile default --output json >/dev/null 2>&1 ||
  fail "AWS default 프로필로 현재 계정을 확인하지 못했습니다."
[[ -f "$COMPOSE_FILE" ]] || fail "Compose 파일을 찾지 못했습니다: $COMPOSE_FILE"

installed=false
if [[ -f "$ENV_FILE" ]]; then installed=true; fi
if docker compose --file "$COMPOSE_FILE" ps -q 2>/dev/null | grep -q .; then
  installed=true
fi
if [[ "$installed" == true ]]; then
  printf '\n기존 실습 플랫폼이 발견되었습니다. 기존 Token과 volume을 보존한 채 다시 Build·설치할까요? [y/N] '
  read -r answer
  [[ "$answer" == "y" || "$answer" == "Y" ]] || {
    printf '설치를 취소했습니다. 기존 플랫폼은 변경하지 않았습니다.\n'
    exit 0
  }
fi

log "2/5" "서비스 Token 환경 파일을 준비합니다."
mkdir -p "$STATE_DIR/guided-gateway"
if [[ ! -f "$ENV_FILE" ]]; then
  umask 077
  {
    printf 'AWS_PROFILE=default\n'
    printf 'LOCAL_UID=%s\n' "$(id -u)"
    printf 'LOCAL_GID=%s\n' "$(id -g)"
    printf 'GUIDED_PROVIDER_MODE=aws\n'
    grep -oE '\$\{[A-Z][A-Z0-9_]+:\?' "$COMPOSE_FILE" |
      sed -E 's/^\$\{([^:]+):\?$/\1/' |
      sort -u |
      while IFS= read -r variable_name; do
        if [[ "$variable_name" == *PASSWORD ]]; then
          printf '%s=%s\n' "$variable_name" "$(openssl rand -hex 18)"
        else
          printf '%s=%s\n' "$variable_name" "$(openssl rand -hex 32)"
        fi
      done
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  printf '새 환경 파일을 만들었습니다: %s\n' "$ENV_FILE"
else
  printf '기존 환경 파일을 재사용합니다: %s\n' "$ENV_FILE"
fi

log "3/5" "Docker·Compose·디스크·포트 상태를 점검합니다."
python3 "$SETUP_ROOT/tools/practice_preflight.py" \
  --root "$SETUP_ROOT" --env-file "$ENV_FILE" --file "$COMPOSE_FILE"

log "4/5" "실습 이미지를 Build하고 공통 플랫폼을 시작합니다."
docker compose --env-file "$ENV_FILE" \
  --file "$COMPOSE_FILE" up -d --build

log "5/5" "설치 결과를 확인합니다."
docker compose --env-file "$ENV_FILE" \
  --file "$COMPOSE_FILE" ps --all

printf '\n설치가 완료되었습니다.\n'
printf 'Control Center: http://127.0.0.1:28097\n'
printf 'NeMo Chat UI:  http://127.0.0.1:28192\n'
printf 'P20 Grafana:    http://127.0.0.1:23002/d/guided-p20\n'
printf 'Grafana 비밀번호 확인: grep -E '\''^(GUIDED_GRAFANA_PASSWORD|GUIDED_P20_GRAFANA_PASSWORD)='\'' %s\n' "$ENV_FILE"
