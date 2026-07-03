#!/bin/bash
# Print the single lab EC2 instance id for the current student.
set -euo pipefail

: "${AWS_PROFILE:?usage: AWS_PROFILE=<profile> AWS_REGION=<region> STUDENT=<id> bash instance-id.sh}"
: "${AWS_REGION:=us-east-1}"
: "${STUDENT:?STUDENT environment variable is required}"

if ! command -v aws >/dev/null 2>&1; then
  echo "ERROR: required command not found: aws" >&2
  exit 1
fi

if ! aws sts get-caller-identity --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "ERROR: AWS credentials are not ready for profile '$AWS_PROFILE' in region '$AWS_REGION'." >&2
  echo "Run aws configure --profile $AWS_PROFILE or aws sso login --profile $AWS_PROFILE, then retry." >&2
  exit 1
fi

ROWS=$(aws ec2 describe-instances --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --filters "Name=tag:Student,Values=$STUDENT" "Name=instance-state-name,Values=stopped,stopping,running,pending" \
  --query "Reservations[].Instances[].[InstanceId,State.Name]" --output text)

COUNT=$(printf "%s\n" "$ROWS" | awk 'NF { count++ } END { print count + 0 }')
if [ "$COUNT" -eq 0 ]; then
  echo "ERROR: no lab instance found for Student=$STUDENT in $AWS_REGION." >&2
  echo "Check AWS_REGION/STUDENT or run terraform apply first." >&2
  exit 1
fi
if [ "$COUNT" -gt 1 ]; then
  echo "ERROR: multiple lab instances found for Student=$STUDENT. Resolve duplicates in the AWS console." >&2
  printf "%s\n" "$ROWS" >&2
  exit 1
fi

printf "%s\n" "$ROWS" | awk 'NF { print $1; exit }'
