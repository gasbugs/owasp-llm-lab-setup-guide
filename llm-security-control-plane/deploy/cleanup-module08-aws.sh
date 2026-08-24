#!/usr/bin/env bash
set -euo pipefail

# Module 08 전용 AWS 리소스만 의존성 역순으로 삭제한다.
# 로컬 Podman 컨테이너와 Module 07 튜토리얼 리소스는 건드리지 않는다.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AWS_REGION=${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
PREFIX=owasp-llm-module08
SOURCE_BUCKET="${PREFIX}-${ACCOUNT_ID}-source"
VECTOR_BUCKET="${PREFIX}-${ACCOUNT_ID}-vectors"
VECTOR_INDEX=guardrail-knowledge
KB_NAME=${PREFIX}-knowledge-base
KB_ROLE=${PREFIX}-knowledge-base-role
KB_ROLE_POLICY=${PREFIX}-knowledge-base-runtime

knowledge_base_id="$(aws bedrock-agent list-knowledge-bases --region "$AWS_REGION" \
  --query "knowledgeBaseSummaries[?name=='${KB_NAME}'].knowledgeBaseId | [0]" \
  --output text)"

if [ -n "$knowledge_base_id" ] && [ "$knowledge_base_id" != None ]; then
  data_source_ids="$(aws bedrock-agent list-data-sources --region "$AWS_REGION" \
    --knowledge-base-id "$knowledge_base_id" \
    --query 'dataSourceSummaries[].dataSourceId' --output text)"
  for data_source_id in $data_source_ids; do
    aws bedrock-agent delete-data-source --region "$AWS_REGION" \
      --knowledge-base-id "$knowledge_base_id" --data-source-id "$data_source_id"
  done
  for _ in $(seq 1 60); do
    remaining="$(aws bedrock-agent list-data-sources --region "$AWS_REGION" \
      --knowledge-base-id "$knowledge_base_id" \
      --query 'length(dataSourceSummaries)' --output text 2>/dev/null || printf '0')"
    [ "$remaining" = 0 ] && break
    sleep 5
  done
  test "$remaining" = 0 || { echo "module08 data source deletion timed out" >&2; exit 1; }

  aws bedrock-agent delete-knowledge-base --region "$AWS_REGION" \
    --knowledge-base-id "$knowledge_base_id"
  for _ in $(seq 1 60); do
    status="$(aws bedrock-agent get-knowledge-base --region "$AWS_REGION" \
      --knowledge-base-id "$knowledge_base_id" --query 'knowledgeBase.status' \
      --output text 2>/dev/null || true)"
    [ -z "$status" ] && break
    sleep 5
  done
  test -z "$status" || { echo "module08 knowledge base deletion timed out" >&2; exit 1; }
fi

aws iam delete-role-policy --role-name "$KB_ROLE" \
  --policy-name "$KB_ROLE_POLICY" 2>/dev/null || true
aws iam delete-role --role-name "$KB_ROLE" 2>/dev/null || true

aws s3 rm "s3://${SOURCE_BUCKET}" --recursive 2>/dev/null || true
aws s3api delete-bucket --region "$AWS_REGION" --bucket "$SOURCE_BUCKET" \
  2>/dev/null || true
aws s3vectors delete-index --region "$AWS_REGION" \
  --vector-bucket-name "$VECTOR_BUCKET" --index-name "$VECTOR_INDEX" \
  2>/dev/null || true
aws s3vectors delete-vector-bucket --region "$AWS_REGION" \
  --vector-bucket-name "$VECTOR_BUCKET" 2>/dev/null || true

rm -f "$ROOT/.state/module08-aws.env" "$ROOT/.state/module08-compose.env"
printf 'module08-aws=DELETED prefix=%s region=%s local_containers=PRESERVED\n' \
  "$PREFIX" "$AWS_REGION"
