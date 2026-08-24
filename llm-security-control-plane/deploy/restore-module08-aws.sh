#!/usr/bin/env bash
set -euo pipefail

# Module 08 전용 Bedrock Knowledge Base를 점검하거나 복구한다.
# 07장의 튜토리얼 리소스와 이름·수명주기를 공유하지 않는다.

MODE=${1:---repair}
case "$MODE" in
  --verify-only|--repair) ;;
  *) echo "usage: $0 [--verify-only|--repair]" >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AWS_REGION=${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}
AWS_PROFILE=${AWS_PROFILE:-default}
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
PREFIX=owasp-llm-module08
SOURCE_BUCKET="${PREFIX}-${ACCOUNT_ID}-source"
VECTOR_BUCKET="${PREFIX}-${ACCOUNT_ID}-vectors"
VECTOR_INDEX=guardrail-knowledge
KB_NAME=${PREFIX}-knowledge-base
DATA_SOURCE_NAME=${PREFIX}-s3-source
KB_ROLE=${PREFIX}-knowledge-base-role
KB_ROLE_POLICY=${PREFIX}-knowledge-base-runtime
VECTOR_BUCKET_ARN="arn:aws:s3vectors:${AWS_REGION}:${ACCOUNT_ID}:bucket/${VECTOR_BUCKET}"
VECTOR_INDEX_ARN="${VECTOR_BUCKET_ARN}/index/${VECTOR_INDEX}"
STATE_DIR="$ROOT/.state"
STATE_FILE="$STATE_DIR/module08-aws.env"
COMPOSE_ENV_FILE="$STATE_DIR/module08-compose.env"

write_compose_env() {
  local current_knowledge_base_id=$1
  install -d -m 0700 "$STATE_DIR"
  umask 077
  {
    printf 'AWS_PROFILE=%s\n' "$AWS_PROFILE"
    printf 'AWS_REGION=%s\n' "$AWS_REGION"
    printf 'LOCAL_UID=%s\n' "$(id -u)"
    printf 'LOCAL_GID=%s\n' "$(id -g)"
    printf 'BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0\n'
    printf 'MODULE08_KNOWLEDGE_BASE_ID=%s\n' "$current_knowledge_base_id"
    printf 'PRESIDIO_INTERNAL_TOKEN=control-plane-nemo-to-presidio\n'
    printf 'APPLICATION_INTERNAL_TOKEN=control-plane-app-to-nemo\n'
    printf 'BEDROCK_GATEWAY_TOKEN=module08-bedrock-gateway-token\n'
    printf 'GUARD_MODE=enforce\n'
    printf 'ASSURANCE_PROFILE=high-assurance\n'
    printf 'ENABLE_LAB_ENDPOINTS=true\n'
    printf 'IMAGE_VERSION=1.0.0\n'
    printf 'DIALOG_IMAGE_VERSION=0.22.0\n'
  } > "$COMPOSE_ENV_FILE"
}

for command in aws jq; do
  command -v "$command" >/dev/null 2>&1 || { echo "required command missing: $command" >&2; exit 1; }
done

wait_for_knowledge_base_absent() {
  local current_id=$1
  local current_status
  for _ in $(seq 1 60); do
    current_status="$(aws bedrock-agent get-knowledge-base --region "$AWS_REGION" \
      --knowledge-base-id "$current_id" --query 'knowledgeBase.status' \
      --output text 2>/dev/null || true)"
    [ -z "$current_status" ] && return 0
    sleep 5
  done
  echo "module08 knowledge base deletion did not complete within 300 seconds" >&2
  exit 1
}

wait_for_knowledge_base_active() {
  local current_id=$1
  local current_status
  for _ in $(seq 1 60); do
    current_status="$(aws bedrock-agent get-knowledge-base --region "$AWS_REGION" \
      --knowledge-base-id "$current_id" --query 'knowledgeBase.status' --output text)"
    case "$current_status" in
      ACTIVE) return 0 ;;
      FAILED|DELETE_UNSUCCESSFUL)
        echo "module08 knowledge base is not recoverable in place: $current_status" >&2
        return 1
        ;;
    esac
    sleep 5
  done
  echo "module08 knowledge base did not become ACTIVE within 300 seconds" >&2
  return 1
}

wait_for_data_source_absent() {
  local current_kb_id=$1
  local current_ds_id=$2
  local current_status
  for _ in $(seq 1 60); do
    current_status="$(aws bedrock-agent get-data-source --region "$AWS_REGION" \
      --knowledge-base-id "$current_kb_id" --data-source-id "$current_ds_id" \
      --query 'dataSource.status' --output text 2>/dev/null || true)"
    [ -z "$current_status" ] && return 0
    sleep 5
  done
  echo "module08 data source deletion did not complete within 300 seconds" >&2
  exit 1
}

wait_for_data_source_available() {
  local current_kb_id=$1
  local current_ds_id=$2
  local current_status
  for _ in $(seq 1 60); do
    current_status="$(aws bedrock-agent get-data-source --region "$AWS_REGION" \
      --knowledge-base-id "$current_kb_id" --data-source-id "$current_ds_id" \
      --query 'dataSource.status' --output text)"
    case "$current_status" in
      AVAILABLE) return 0 ;;
      FAILED|DELETE_UNSUCCESSFUL) return 1 ;;
    esac
    sleep 5
  done
  return 1
}

knowledge_base_id="$(aws bedrock-agent list-knowledge-bases --region "$AWS_REGION" \
  --query "knowledgeBaseSummaries[?name=='${KB_NAME}'].knowledgeBaseId | [0]" \
  --output text)"

if [ "$MODE" = --verify-only ]; then
  test -n "$knowledge_base_id" && test "$knowledge_base_id" != None || {
    echo "module08-aws=MISSING action=run --repair" >&2
    exit 1
  }
  knowledge_base_status="$(aws bedrock-agent get-knowledge-base --region "$AWS_REGION" \
    --knowledge-base-id "$knowledge_base_id" \
    --query 'knowledgeBase.status' --output text)"
  test "$knowledge_base_status" = ACTIVE || {
    echo "module08-aws=NOT_READY status=$knowledge_base_status" >&2
    exit 1
  }
  data_source_id="$(aws bedrock-agent list-data-sources --region "$AWS_REGION" \
    --knowledge-base-id "$knowledge_base_id" \
    --query "dataSourceSummaries[?name=='${DATA_SOURCE_NAME}'].dataSourceId | [0]" \
    --output text)"
  test -n "$data_source_id" && test "$data_source_id" != None || {
    echo "module08-aws=NOT_READY data_source=MISSING" >&2
    exit 1
  }
  data_source_status="$(aws bedrock-agent get-data-source --region "$AWS_REGION" \
    --knowledge-base-id "$knowledge_base_id" --data-source-id "$data_source_id" \
    --query 'dataSource.status' --output text)"
  test "$data_source_status" = AVAILABLE || {
    echo "module08-aws=NOT_READY data_source_status=$data_source_status" >&2
    exit 1
  }
  ingestion_status="$(aws bedrock-agent list-ingestion-jobs --region "$AWS_REGION" \
    --knowledge-base-id "$knowledge_base_id" --data-source-id "$data_source_id" \
    --max-results 1 --query 'ingestionJobSummaries[0].status' --output text)"
  test "$ingestion_status" = COMPLETE || {
    echo "module08-aws=NOT_READY ingestion_status=$ingestion_status" >&2
    exit 1
  }
  write_compose_env "$knowledge_base_id"
  printf 'module08-aws=READY knowledge_base_id=%s data_source_id=%s ingestion_status=%s region=%s\n' \
    "$knowledge_base_id" "$data_source_id" "$ingestion_status" "$AWS_REGION"
  exit 0
fi

if [ -n "$knowledge_base_id" ] && [ "$knowledge_base_id" != None ]; then
  knowledge_base_status="$(aws bedrock-agent get-knowledge-base --region "$AWS_REGION" \
    --knowledge-base-id "$knowledge_base_id" --query 'knowledgeBase.status' --output text)"
  case "$knowledge_base_status" in
    FAILED|DELETE_UNSUCCESSFUL)
      aws bedrock-agent delete-knowledge-base --region "$AWS_REGION" \
        --knowledge-base-id "$knowledge_base_id"
      wait_for_knowledge_base_absent "$knowledge_base_id"
      knowledge_base_id=None
      ;;
    DELETING)
      wait_for_knowledge_base_absent "$knowledge_base_id"
      knowledge_base_id=None
      ;;
    ACTIVE) ;;
    *) wait_for_knowledge_base_active "$knowledge_base_id" ;;
  esac
fi

aws s3api head-bucket --bucket "$SOURCE_BUCKET" >/dev/null 2>&1 \
  || aws s3api create-bucket --region "$AWS_REGION" --bucket "$SOURCE_BUCKET" >/dev/null
aws s3api put-public-access-block --region "$AWS_REGION" --bucket "$SOURCE_BUCKET" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3 cp "$ROOT/aws/documents/" "s3://${SOURCE_BUCKET}/knowledge/" \
  --recursive --exclude '*' --include '*.md'

aws s3vectors get-vector-bucket --region "$AWS_REGION" \
  --vector-bucket-name "$VECTOR_BUCKET" >/dev/null 2>&1 \
  || aws s3vectors create-vector-bucket --region "$AWS_REGION" \
    --vector-bucket-name "$VECTOR_BUCKET" >/dev/null
aws s3vectors get-index --region "$AWS_REGION" --vector-bucket-name "$VECTOR_BUCKET" \
  --index-name "$VECTOR_INDEX" >/dev/null 2>&1 \
  || aws s3vectors create-index --region "$AWS_REGION" \
    --vector-bucket-name "$VECTOR_BUCKET" --index-name "$VECTOR_INDEX" \
    --data-type float32 --dimension 1024 --distance-metric cosine >/dev/null

jq -n --arg account "$ACCOUNT_ID" --arg region "$AWS_REGION" \
  -f "$ROOT/aws/policies/trust-policy.jq" > /tmp/module08-kb-trust-policy.json
jq -n --arg region "$AWS_REGION" --arg source "arn:aws:s3:::${SOURCE_BUCKET}" \
  --arg vector "$VECTOR_BUCKET_ARN" --arg index "$VECTOR_INDEX_ARN" \
  -f "$ROOT/aws/policies/runtime-policy.jq" > /tmp/module08-kb-runtime-policy.json
aws iam get-role --role-name "$KB_ROLE" >/dev/null 2>&1 \
  || aws iam create-role --role-name "$KB_ROLE" \
    --assume-role-policy-document file:///tmp/module08-kb-trust-policy.json >/dev/null
aws iam update-assume-role-policy --role-name "$KB_ROLE" \
  --policy-document file:///tmp/module08-kb-trust-policy.json
aws iam put-role-policy --role-name "$KB_ROLE" --policy-name "$KB_ROLE_POLICY" \
  --policy-document file:///tmp/module08-kb-runtime-policy.json

if [ -z "$knowledge_base_id" ] || [ "$knowledge_base_id" = None ]; then
  sleep 10
  knowledge_base_id="$(aws bedrock-agent create-knowledge-base --region "$AWS_REGION" \
    --name "$KB_NAME" --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/${KB_ROLE}" \
    --knowledge-base-configuration \
    "{\"type\":\"VECTOR\",\"vectorKnowledgeBaseConfiguration\":{\"embeddingModelArn\":\"arn:aws:bedrock:${AWS_REGION}::foundation-model/amazon.titan-embed-text-v2:0\",\"embeddingModelConfiguration\":{\"bedrockEmbeddingModelConfiguration\":{\"dimensions\":1024,\"embeddingDataType\":\"FLOAT32\"}}}}" \
    --storage-configuration \
    "{\"type\":\"S3_VECTORS\",\"s3VectorsConfiguration\":{\"indexArn\":\"${VECTOR_INDEX_ARN}\"}}" \
    --query 'knowledgeBase.knowledgeBaseId' --output text)"
  wait_for_knowledge_base_active "$knowledge_base_id"
fi

data_source_id="$(aws bedrock-agent list-data-sources --region "$AWS_REGION" \
  --knowledge-base-id "$knowledge_base_id" \
  --query "dataSourceSummaries[?name=='${DATA_SOURCE_NAME}'].dataSourceId | [0]" \
  --output text)"
if [ -z "$data_source_id" ] || [ "$data_source_id" = None ]; then
  data_source_id="$(aws bedrock-agent create-data-source --region "$AWS_REGION" \
    --knowledge-base-id "$knowledge_base_id" --name "$DATA_SOURCE_NAME" \
    --data-deletion-policy DELETE --data-source-configuration \
    "{\"type\":\"S3\",\"s3Configuration\":{\"bucketArn\":\"arn:aws:s3:::${SOURCE_BUCKET}\",\"inclusionPrefixes\":[\"knowledge/\"]}}" \
    --vector-ingestion-configuration \
    '{"chunkingConfiguration":{"chunkingStrategy":"FIXED_SIZE","fixedSizeChunkingConfiguration":{"maxTokens":300,"overlapPercentage":10}}}' \
    --query 'dataSource.dataSourceId' --output text)"
  wait_for_data_source_available "$knowledge_base_id" "$data_source_id"
else
  data_source_status="$(aws bedrock-agent get-data-source --region "$AWS_REGION" \
    --knowledge-base-id "$knowledge_base_id" --data-source-id "$data_source_id" \
    --query 'dataSource.status' --output text)"
  case "$data_source_status" in
    FAILED|DELETE_UNSUCCESSFUL)
      aws bedrock-agent delete-data-source --region "$AWS_REGION" \
        --knowledge-base-id "$knowledge_base_id" --data-source-id "$data_source_id"
      wait_for_data_source_absent "$knowledge_base_id" "$data_source_id"
      data_source_id="$(aws bedrock-agent create-data-source --region "$AWS_REGION" \
        --knowledge-base-id "$knowledge_base_id" --name "$DATA_SOURCE_NAME" \
        --data-deletion-policy DELETE --data-source-configuration \
        "{\"type\":\"S3\",\"s3Configuration\":{\"bucketArn\":\"arn:aws:s3:::${SOURCE_BUCKET}\",\"inclusionPrefixes\":[\"knowledge/\"]}}" \
        --vector-ingestion-configuration \
        '{"chunkingConfiguration":{"chunkingStrategy":"FIXED_SIZE","fixedSizeChunkingConfiguration":{"maxTokens":300,"overlapPercentage":10}}}' \
        --query 'dataSource.dataSourceId' --output text)"
      wait_for_data_source_available "$knowledge_base_id" "$data_source_id"
      ;;
    DELETING)
      wait_for_data_source_absent "$knowledge_base_id" "$data_source_id"
      data_source_id="$(aws bedrock-agent create-data-source --region "$AWS_REGION" \
        --knowledge-base-id "$knowledge_base_id" --name "$DATA_SOURCE_NAME" \
        --data-deletion-policy DELETE --data-source-configuration \
        "{\"type\":\"S3\",\"s3Configuration\":{\"bucketArn\":\"arn:aws:s3:::${SOURCE_BUCKET}\",\"inclusionPrefixes\":[\"knowledge/\"]}}" \
        --vector-ingestion-configuration \
        '{"chunkingConfiguration":{"chunkingStrategy":"FIXED_SIZE","fixedSizeChunkingConfiguration":{"maxTokens":300,"overlapPercentage":10}}}' \
        --query 'dataSource.dataSourceId' --output text)"
      wait_for_data_source_available "$knowledge_base_id" "$data_source_id"
      ;;
    AVAILABLE) ;;
    *) wait_for_data_source_available "$knowledge_base_id" "$data_source_id" ;;
  esac
fi
ingestion_job_id="$(aws bedrock-agent start-ingestion-job --region "$AWS_REGION" \
  --knowledge-base-id "$knowledge_base_id" --data-source-id "$data_source_id" \
  --query 'ingestionJob.ingestionJobId' --output text)"

ingestion_status=STARTING
for _ in $(seq 1 60); do
  ingestion_status="$(aws bedrock-agent get-ingestion-job --region "$AWS_REGION" \
    --knowledge-base-id "$knowledge_base_id" --data-source-id "$data_source_id" \
    --ingestion-job-id "$ingestion_job_id" --query 'ingestionJob.status' --output text)"
  case "$ingestion_status" in
    COMPLETE) break ;;
    FAILED|STOPPED) echo "module08 ingestion failed: $ingestion_status" >&2; exit 1 ;;
  esac
  sleep 5
done
test "$ingestion_status" = COMPLETE || {
  echo "module08 ingestion did not complete within 300 seconds" >&2
  exit 1
}

install -d -m 0700 "$STATE_DIR"
umask 077
{
  printf 'MODULE08_KNOWLEDGE_BASE_ID=%q\n' "$knowledge_base_id"
  printf 'MODULE08_DATA_SOURCE_ID=%q\n' "$data_source_id"
  printf 'MODULE08_INGESTION_JOB_ID=%q\n' "$ingestion_job_id"
  printf 'AWS_REGION=%q\n' "$AWS_REGION"
} > "$STATE_FILE"
write_compose_env "$knowledge_base_id"
printf 'module08-aws=RESTORED knowledge_base_id=%s ingestion_job_id=%s state=%s compose_env=%s\n' \
  "$knowledge_base_id" "$ingestion_job_id" "$STATE_FILE" "$COMPOSE_ENV_FILE"
