#!/usr/bin/env bash
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
PREFIX="${KB_PREFIX:-owasp-llm-course}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.knowledge-base.env"
DOC_DIR="$ROOT_DIR/knowledge-base/documents"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
SOURCE_BUCKET="${PREFIX}-${ACCOUNT_ID}-source"
VECTOR_BUCKET="${PREFIX}-${ACCOUNT_ID}-vectors"
INDEX_NAME="course-knowledge"
ROLE_NAME="${PREFIX}-knowledge-base-role"
POLICY_NAME="${PREFIX}-knowledge-base-runtime"
ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
VECTOR_BUCKET_ARN="arn:aws:s3vectors:${REGION}:${ACCOUNT_ID}:bucket/${VECTOR_BUCKET}"
INDEX_ARN="${VECTOR_BUCKET_ARN}/index/${INDEX_NAME}"

for command in aws jq; do
  command -v "$command" >/dev/null || { printf '%s is required\n' "$command" >&2; exit 1; }
done
[[ ! -f "$ENV_FILE" ]] || { printf 'Run scripts/delete-knowledge-base.sh first.\n' >&2; exit 1; }

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
jq -n --arg account "$ACCOUNT_ID" --arg region "$REGION" '{Version:"2012-10-17",Statement:[{
  Effect:"Allow",Principal:{Service:"bedrock.amazonaws.com"},Action:"sts:AssumeRole",
  Condition:{StringEquals:{"aws:SourceAccount":$account},ArnLike:{"aws:SourceArn":("arn:aws:bedrock:"+$region+":"+$account+":knowledge-base/*")}}
}]}' > "$TMP_DIR/trust.json"
jq -n --arg region "$REGION" --arg source "arn:aws:s3:::$SOURCE_BUCKET" \
  --arg vector "$VECTOR_BUCKET_ARN" --arg index "$INDEX_ARN" '{Version:"2012-10-17",Statement:[
  {Effect:"Allow",Action:"bedrock:InvokeModel",Resource:("arn:aws:bedrock:"+$region+"::foundation-model/amazon.titan-embed-text-v2:0")},
  {Effect:"Allow",Action:"s3:ListBucket",Resource:$source},
  {Effect:"Allow",Action:"s3:GetObject",Resource:($source+"/knowledge/*")},
  {Effect:"Allow",Action:["s3vectors:DeleteVectors","s3vectors:GetIndex","s3vectors:GetVectors","s3vectors:PutVectors","s3vectors:QueryVectors"],Resource:[$vector,$index]}
]}' > "$TMP_DIR/policy.json"

aws s3api create-bucket --region "$REGION" --bucket "$SOURCE_BUCKET"
aws s3api put-public-access-block --region "$REGION" --bucket "$SOURCE_BUCKET" \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3 cp "$DOC_DIR/" "s3://$SOURCE_BUCKET/knowledge/" --recursive --exclude '*' --include '*.md'
aws s3vectors create-vector-bucket --region "$REGION" --vector-bucket-name "$VECTOR_BUCKET"
aws s3vectors create-index --region "$REGION" --vector-bucket-name "$VECTOR_BUCKET" \
  --index-name "$INDEX_NAME" --data-type float32 --dimension 1024 --distance-metric cosine
aws iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document "file://$TMP_DIR/trust.json" >/dev/null
aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY_NAME" \
  --policy-document "file://$TMP_DIR/policy.json"

sleep 10
KB_ID="$(aws bedrock-agent create-knowledge-base --region "$REGION" \
  --name "${PREFIX}-knowledge-base" --role-arn "$ROLE_ARN" \
  --knowledge-base-configuration "{\"type\":\"VECTOR\",\"vectorKnowledgeBaseConfiguration\":{\"embeddingModelArn\":\"arn:aws:bedrock:${REGION}::foundation-model/amazon.titan-embed-text-v2:0\",\"embeddingModelConfiguration\":{\"bedrockEmbeddingModelConfiguration\":{\"dimensions\":1024,\"embeddingDataType\":\"FLOAT32\"}}}}" \
  --storage-configuration "{\"type\":\"S3_VECTORS\",\"s3VectorsConfiguration\":{\"indexArn\":\"${INDEX_ARN}\"}}" \
  --query 'knowledgeBase.knowledgeBaseId' --output text)"
DATA_SOURCE_ID="$(aws bedrock-agent create-data-source --region "$REGION" \
  --knowledge-base-id "$KB_ID" --name "${PREFIX}-s3-source" --data-deletion-policy DELETE \
  --data-source-configuration "{\"type\":\"S3\",\"s3Configuration\":{\"bucketArn\":\"arn:aws:s3:::${SOURCE_BUCKET}\",\"inclusionPrefixes\":[\"knowledge/\"]}}" \
  --vector-ingestion-configuration '{"chunkingConfiguration":{"chunkingStrategy":"FIXED_SIZE","fixedSizeChunkingConfiguration":{"maxTokens":300,"overlapPercentage":10}}}' \
  --query 'dataSource.dataSourceId' --output text)"

cat > "$ENV_FILE" <<EOF
export AWS_REGION='$REGION'
export KNOWLEDGE_BASE_ID='$KB_ID'
export DATA_SOURCE_ID='$DATA_SOURCE_ID'
export KNOWLEDGE_SOURCE_BUCKET='$SOURCE_BUCKET'
export KNOWLEDGE_VECTOR_BUCKET='$VECTOR_BUCKET'
export KNOWLEDGE_VECTOR_INDEX='$INDEX_NAME'
export KNOWLEDGE_BASE_ROLE='$ROLE_NAME'
export KNOWLEDGE_BASE_ROLE_POLICY='$POLICY_NAME'
EOF
printf 'Created Knowledge Base %s and data source %s\n' "$KB_ID" "$DATA_SOURCE_ID"
printf 'Run: source %q\n' "$ENV_FILE"
