#!/bin/bash
# Print the single EC2 instance id owned by the account's lab ASG.
set -euo pipefail

: "${AWS_PROFILE:?usage: AWS_PROFILE=<profile> AWS_REGION=<region> bash instance-id.sh}"
: "${AWS_REGION:=us-east-1}"

if ! command -v aws >/dev/null 2>&1; then
  echo "ERROR: required command not found: aws" >&2
  exit 1
fi

if ! aws sts get-caller-identity --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "ERROR: AWS credentials are not ready for profile '$AWS_PROFILE' in region '$AWS_REGION'." >&2
  echo "Run aws configure --profile $AWS_PROFILE or aws sso login --profile $AWS_PROFILE, then retry." >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ASG_NAME=$(bash "$SCRIPT_DIR/asg-name.sh")
ROWS=$(aws autoscaling describe-auto-scaling-groups \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --auto-scaling-group-names "$ASG_NAME" \
  --query "AutoScalingGroups[0].Instances[].InstanceId" \
  --output text)

COUNT=$(printf "%s\n" "$ROWS" | awk '{ for (i = 1; i <= NF; i++) count++ } END { print count + 0 }')
if [ "$COUNT" -eq 0 ]; then
  echo "ERROR: ASG $ASG_NAME has no instance in $AWS_REGION." >&2
  echo "Run start-lab.sh first." >&2
  exit 1
fi
if [ "$COUNT" -gt 1 ]; then
  echo "ERROR: ASG $ASG_NAME has multiple instances; expected exactly one." >&2
  printf "%s\n" "$ROWS" >&2
  exit 1
fi

printf "%s\n" "$ROWS" | awk 'NF { print $1; exit }'
