#!/usr/bin/env bash
set -euo pipefail

# Knowledge Base를 만들기 전에 Nova Lite 실습에 필요한 로컬 secret 상태만 준비한다.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE_DIR=${MODULE08_STATE_DIR:-"$ROOT/.state"}
COMPOSE_ENV_FILE="$STATE_DIR/module08-compose.env"

for command in aws openssl; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command missing: $command" >&2
    exit 1
  }
done

AWS_REGION=${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}
AWS_PROFILE=${AWS_PROFILE:-default}
export AWS_REGION AWS_PROFILE

aws sts get-caller-identity --query '{Account:Account,Arn:Arn}' --output json >/dev/null

# shellcheck source=deploy/lib/module08-compose-env.sh
source "$ROOT/deploy/lib/module08-compose-env.sh"
write_module08_compose_env "$STATE_DIR" "$COMPOSE_ENV_FILE" ""

printf 'module08-runtime=READY region=%s compose_env=%s knowledge_base=DEFERRED\n' \
  "$AWS_REGION" "$COMPOSE_ENV_FILE"
