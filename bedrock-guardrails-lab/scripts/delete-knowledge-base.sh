#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.knowledge-base.env"
[[ -f "$ENV_FILE" ]] || { printf 'Nothing to delete.\n'; exit 0; }
# shellcheck disable=SC1090
source "$ENV_FILE"

aws bedrock-agent delete-data-source --region "$AWS_REGION" \
  --knowledge-base-id "$KNOWLEDGE_BASE_ID" --data-source-id "$DATA_SOURCE_ID"
aws bedrock-agent delete-knowledge-base --region "$AWS_REGION" --knowledge-base-id "$KNOWLEDGE_BASE_ID"
aws s3 rm "s3://$KNOWLEDGE_SOURCE_BUCKET" --recursive
aws s3api delete-bucket --region "$AWS_REGION" --bucket "$KNOWLEDGE_SOURCE_BUCKET"
aws s3vectors delete-index --region "$AWS_REGION" \
  --vector-bucket-name "$KNOWLEDGE_VECTOR_BUCKET" --index-name "$KNOWLEDGE_VECTOR_INDEX"
aws s3vectors delete-vector-bucket --region "$AWS_REGION" --vector-bucket-name "$KNOWLEDGE_VECTOR_BUCKET"
aws iam delete-role-policy --role-name "$KNOWLEDGE_BASE_ROLE" --policy-name "$KNOWLEDGE_BASE_ROLE_POLICY"
aws iam delete-role --role-name "$KNOWLEDGE_BASE_ROLE"
rm -f "$ENV_FILE"
printf 'Knowledge Base lab resources deleted.\n'
