#!/usr/bin/env bash
# Recreate the chapter 02-04 evaluation stack with fresh local credentials.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KNOWLEDGE_BASE_ID=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --knowledge-base-id)
      [ "$#" -ge 2 ] || { echo 'Missing Knowledge Base ID' >&2; exit 2; }
      KNOWLEDGE_BASE_ID="$2"
      [[ "$KNOWLEDGE_BASE_ID" =~ ^[A-Za-z0-9]{10}$ ]] || { echo 'Invalid Knowledge Base ID' >&2; exit 2; }
      shift 2 ;;
    --help)
      echo 'Usage: bash prepare-evaluation-environment.sh [--knowledge-base-id ID]'
      echo 'Builds four services, removes the six named lab containers, backs up .state, and creates fresh tokens.'
      echo 'Keeps ~/.aws and learner work files; ensures the lab Knowledge Base when no ID is supplied.'
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

START_SECONDS=$SECONDS
CURRENT_STAGE="실행 확인"
PREPARATION_DIR=""
BACKUP_DIR="아직 없음 (백업 단계 전)"
REMOVED_COUNT=0
RESET_STARTED=false
KB_ACTION="직접 지정"
log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
stage() { CURRENT_STAGE="$2"; log "[$1/8] $2"; }
finish() {
  local result=$?
  trap - EXIT
  if [ "$result" -ne 0 ]; then
    printf '\n[ERR] 준비 중단: %s (종료 코드 %s, %s초)\n' "$CURRENT_STAGE" "$result" "$((SECONDS-START_SECONDS))" >&2
    if [ "$RESET_STARTED" = false ]; then
      printf '기존 컨테이너·.state: 이번 실행에서 변경하지 않음\n' >&2
    else
      printf '컨테이너 정리 시작됨: 제거 완료 %s개. 상태 백업: %s\n' "$REMOVED_COUNT" "$BACKUP_DIR" >&2
    fi
    printf 'AWS 준비에서 생성·수정한 자원은 자동 삭제하지 않습니다. 위 오류를 먼저 확인하세요.\n' >&2
  fi
  [ -z "$PREPARATION_DIR" ] || rm -rf "$PREPARATION_DIR"
  exit "$result"
}

printf '평가 환경을 새로 준비합니다. 아래 컨테이너가 있으면 삭제합니다.\n'
printf '삭제 조건: llm-security-control-plane network 소속이며 아래 이름에 일치하는 컨테이너만 대상입니다.\n'
printf '  llm-security-application-gateway\n  llm-security-nemo-hub\n  llm-security-presidio-spoke\n  llm-security-bedrock-gateway\n  llm-security-nemo-dialog-rails\n  guardrails-presidio-api\n'
printf '컨테이너 내부에서만 수정한 파일은 삭제됩니다.\n'
printf '기존 상태: %s/.state → setup 루트 .state/control-plane-backup-날짜로 백업\n' "$ROOT"
printf '서비스 Token·로그인 상태는 새로 생성합니다. 이전 JWT는 사용할 수 없습니다.\n'
printf '~/.aws·작업 파일·이미지·network는 유지합니다. 실습 Knowledge Base는 재사용하거나 생성·복구합니다.\n'
printf '실습 전용 Knowledge Base나 Data Source가 실패 상태이면 복구 과정에서 삭제 후 재생성될 수 있습니다. S3 원문은 유지합니다.\n'
printf '계속하려면 y를 입력하세요 [y/N]: '
if ! IFS= read -r confirmation || [ "$confirmation" != y ]; then
  printf '취소했습니다. 컨테이너·상태·AWS 자원을 변경하지 않았습니다.\n'
  exit 0
fi
trap finish EXIT
log '사용자 확인 완료. AWS 준비와 이미지 빌드가 끝난 뒤 기존 컨테이너를 정리합니다.'
stage 1 '필수 명령·Docker·AWS 인증 확인'
for tool in docker aws openssl curl jq; do
  command -v "$tool" >/dev/null || { echo "Required command missing: $tool" >&2; exit 1; }
done
docker info >/dev/null
docker compose version >/dev/null
# A matching name on another tenant network must never be removed or recreated.
for container in llm-security-application-gateway llm-security-nemo-hub \
  llm-security-presidio-spoke llm-security-bedrock-gateway; do
  existing="$(docker ps -aq --filter "name=^/${container}$")"
  owned="$(docker ps -aq --filter "name=^/${container}$" --filter network=llm-security-control-plane)"
  if [ -n "$existing" ] && [ -z "$owned" ]; then
    printf '다른 network에 같은 이름의 컨테이너가 있어 중단합니다: %s\n' "$container" >&2
    exit 1
  fi
done
[ -d "$HOME/.aws" ] || { echo 'AWS configuration directory missing: ~/.aws' >&2; exit 1; }
AWS_SHARED_CREDENTIALS_FILE="$HOME/.aws/credentials" AWS_CONFIG_FILE="$HOME/.aws/config" \
  aws sts get-caller-identity --profile default --region us-east-1 >/dev/null

log 'Docker와 AWS default Profile 인증 확인 완료 (us-east-1).'
stage 2 '새 서비스 Token과 평가 설정 준비'
# Build first so a build failure does not destroy the previous runtime or state.
# This temporary directory also lives under the Git-ignored setup .state.
mkdir -p "$ROOT/../.state"
PREPARATION_DIR="$(mktemp -d "$ROOT/../.state/evaluation-preparation-XXXXXXXX")"
ENV_FILE="$PREPARATION_DIR/module08-compose.env"
(
  umask 077
  cat > "$ENV_FILE" <<ENV
AWS_PROFILE=default
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0
MODULE08_KNOWLEDGE_BASE_ID=$KNOWLEDGE_BASE_ID
PRESIDIO_INTERNAL_TOKEN=$(openssl rand -hex 24)
APPLICATION_INTERNAL_TOKEN=$(openssl rand -hex 24)
BEDROCK_GATEWAY_TOKEN=$(openssl rand -hex 24)
TELEMETRY_INGEST_TOKEN=$(openssl rand -hex 24)
TELEMETRY_HMAC_KEY=$(openssl rand -hex 32)
LLM_MONITOR_TOKEN=$(openssl rand -hex 24)
LLM_MONITOR_ADMIN_TOKEN=$(openssl rand -hex 24)
RETRIEVAL_SERVICE_TOKEN=$(openssl rand -hex 24)
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=$(openssl rand -hex 18)
AUTH_ADMIN_TOKEN=$(openssl rand -hex 24)
GUARD_MODE=enforce
ASSURANCE_PROFILE=high-assurance
LEGACY_STATIC_TOKEN_MODE=false
CONTROL_PLANE_POLICY_SOURCE=$ROOT/policies/evaluation-control-plane-policy.yaml
NEMO_CONFIG_SOURCE=$ROOT/nemo-policy-hub/config
ENABLE_LAB_ENDPOINTS=true
IMAGE_VERSION=1.0.0
LOCAL_UID=$(id -u)
LOCAL_GID=$(id -g)
BEDROCK_HOST_PORT=18096
PRESIDIO_HOST_PORT=18093
HUB_HOST_PORT=18094
APPLICATION_HOST_PORT=18095
CONTROL_PLANE_NETWORK_NAME=llm-security-control-plane
ENV
)
# Load generated values literally; never execute an old learner environment file.
while IFS='=' read -r name value; do
  export "$name=$value"
done < "$ENV_FILE"
export AWS_CREDENTIALS_DIR="$HOME/.aws"
export PRESIDIO_POLICY_SOURCE="$ROOT/spokes/presidio-privacy/policy.py"
export APPLICATION_POLICY_SOURCE="$ROOT/policies/application-policy.yaml"
export AUTH_EVENT_SINK=stdout SECURITY_MONITOR_URL= OTEL_EXPORTER_OTLP_ENDPOINT=
compose() {
  docker compose --project-name llm-security-control-plane \
    --env-file "$ENV_FILE" -f "$ROOT/compose.yaml" "$@"
}
stage 3 '네 서비스 이미지 빌드 (다운로드 때문에 시간이 걸릴 수 있음)'
compose config --quiet
compose build bedrock-gateway presidio nemo-hub application

log '네 서비스 이미지 빌드 완료.'
stage 4 'Knowledge Base 탐색·생성·문서 수집'
# Resolve AWS resources before removing the previous containers or local state.
export AWS_PROFILE=default AWS_REGION=us-east-1
export AWS_SHARED_CREDENTIALS_FILE="$HOME/.aws/credentials" AWS_CONFIG_FILE="$HOME/.aws/config"
if [ -z "$KNOWLEDGE_BASE_ID" ]; then
  MODULE08_AWS_STATE_DIR="$PREPARATION_DIR/aws" \
    bash "$ROOT/deploy/restore-module08-aws.sh" --ensure | tee "$PREPARATION_DIR/knowledge-base.log"
  KB_ACTION="$(sed -n 's/^module08-aws=\(READY\|RESTORED\).*/\1/p' "$PREPARATION_DIR/knowledge-base.log" | tail -n 1)"
  case "$KB_ACTION" in
    READY) KB_ACTION="기존 실습 저장소 재사용" ;;
    RESTORED) KB_ACTION="실습 저장소 생성 또는 복구·문서 수집 완료" ;;
    *) KB_ACTION="실습 저장소 준비 완료" ;;
  esac
  KNOWLEDGE_BASE_ID="$(sed -n 's/^MODULE08_KNOWLEDGE_BASE_ID=//p' "$PREPARATION_DIR/aws/module08-aws.env")"
else
  status="$(aws bedrock-agent get-knowledge-base --region us-east-1 \
    --knowledge-base-id "$KNOWLEDGE_BASE_ID" --query 'knowledgeBase.status' --output text)"
  [ "$status" = ACTIVE ] || { echo "Knowledge Base is not ACTIVE: $status" >&2; exit 1; }
fi
[[ "$KNOWLEDGE_BASE_ID" =~ ^[A-Za-z0-9]{10}$ ]] || { echo 'Knowledge Base resolution failed' >&2; exit 1; }
sed -i "s/^MODULE08_KNOWLEDGE_BASE_ID=.*/MODULE08_KNOWLEDGE_BASE_ID=$KNOWLEDGE_BASE_ID/" "$ENV_FILE"
export MODULE08_KNOWLEDGE_BASE_ID="$KNOWLEDGE_BASE_ID"
printf 'evaluation-knowledge-base=%s region=us-east-1\n' "$KNOWLEDGE_BASE_ID"

log "Knowledge Base 준비 완료: $KNOWLEDGE_BASE_ID ($KB_ACTION)."
stage 5 '이전 실습 컨테이너 6개 정리'
# Only explicitly named chapter containers can be removed; Docker errors propagate.
for container in llm-security-application-gateway llm-security-nemo-hub \
  llm-security-presidio-spoke llm-security-bedrock-gateway \
  llm-security-nemo-dialog-rails guardrails-presidio-api; do
  found="$(docker ps -aq --filter "name=^/${container}$" --filter network=llm-security-control-plane)"
  if [ -n "$found" ]; then
    RESET_STARTED=true
    docker rm -f "$container" >/dev/null
    REMOVED_COUNT=$((REMOVED_COUNT+1))
    log "제거 완료: $container"
  else
    log "건너뜀 (대상 network에 컨테이너 없음): $container"
  fi
done

stage 6 '기존 .state 백업·새 인증 상태 적용'
if [ -e "$ROOT/.state" ]; then
  RESET_STARTED=true
  BACKUP_DIR="$ROOT/../.state/control-plane-backup-$(date +%Y%m%d-%H%M%S-%N)"
  mv "$ROOT/.state" "$BACKUP_DIR"
  printf 'previous-state-backup=%s\n' "$BACKUP_DIR"
else
  BACKUP_DIR="없음 (기존 .state 없음)"
fi
RESET_STARTED=true
mkdir -p "$ROOT/.state/application-auth"
mv "$ENV_FILE" "$ROOT/.state/module08-compose.env"
ENV_FILE="$ROOT/.state/module08-compose.env"
if [ -f "$PREPARATION_DIR/aws/module08-aws.env" ]; then
  cp "$PREPARATION_DIR/aws/module08-aws.env" "$ROOT/.state/module08-aws.env"
fi
log "새 설정 파일: $ROOT/.state/module08-compose.env (0600, 비밀값은 표시하지 않음)."
stage 7 '네 서비스 시작·준비 대기 (최대 180초)'
compose up -d --force-recreate --wait --wait-timeout 180 \
  bedrock-gateway presidio nemo-hub application
compose ps -a
stage 8 '서비스 health와 적용 정책 확인'
for url in http://127.0.0.1:18096/healthz http://127.0.0.1:18093/healthz \
  http://127.0.0.1:18094/healthz http://127.0.0.1:18095/healthz; do
  curl -fsS --max-time 10 "$url" | jq -e '.ok == true' >/dev/null
  log "준비 검사 통과: $url"
done
curl -fsS --max-time 10 http://127.0.0.1:18094/api/guardrails/policy \
  | jq -e '.guard_mode == "enforce" and .assurance_profile == "high-assurance" and
           .presidio_failure_mode == "closed" and .main_task.id == "account-security-support-v1"' >/dev/null
printf 'evaluation-environment=READY app=http://127.0.0.1:18095 mode=enforce profile=high-assurance auth=jwt presidio-failure=closed\n'
printf '\n===== 평가 환경 준비 결과 =====\n'
printf '결과: READY · 소요 시간: %s초\n' "$((SECONDS-START_SECONDS))"
printf '서비스: 4개 시작 및 health 확인 완료\n'
printf 'Application: http://127.0.0.1:18095\nNeMo Hub: http://127.0.0.1:18094\nPresidio: http://127.0.0.1:18093\nBedrock Gateway: http://127.0.0.1:18096\n'
printf 'Knowledge Base: %s · %s · us-east-1\n' "$KNOWLEDGE_BASE_ID" "$KB_ACTION"
printf '적용 정책: enforce · high-assurance · Presidio 장애 시 closed\n'
printf '업무 정책: account-security-support-v1 · 인증: JWT (새 인증 상태)\n'
printf '이전 컨테이너: %s개 제거 · 상태 백업: %s\n' "$REMOVED_COUNT" "$BACKUP_DIR"
printf '환경 파일: %s/.state/module08-compose.env (0600)\n' "$ROOT"
printf '다음 단계: Promptfoo 실습에서 새로 로그인해 정상·위험 요청을 확인하세요.\n'
printf '확인 범위: 서비스 준비와 정책 적용. Main Model 답변·검색·공격 방어 검증은 아직 수행하지 않았습니다.\n'
