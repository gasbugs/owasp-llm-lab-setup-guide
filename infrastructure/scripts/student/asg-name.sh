#!/bin/bash
# Print the single lab Auto Scaling Group name in this AWS account and region.
set -euo pipefail

: "${AWS_PROFILE:?usage: AWS_PROFILE=<profile> AWS_REGION=<region> bash asg-name.sh}"
: "${AWS_REGION:=us-east-1}"

ROWS=$(aws autoscaling describe-auto-scaling-groups \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --query "AutoScalingGroups[?Tags[?Key=='Project' && Value=='owasp-top-10-for-llm']].AutoScalingGroupName" \
  --output text)

COUNT=$(printf "%s\n" "$ROWS" | awk '{ for (i = 1; i <= NF; i++) count++ } END { print count + 0 }')
if [ "$COUNT" -eq 0 ]; then
  echo "ERROR: no OWASP LLM lab ASG found in $AWS_REGION." >&2
  echo "Check AWS_PROFILE/AWS_REGION or run terraform apply first." >&2
  exit 1
fi
if [ "$COUNT" -gt 1 ]; then
  echo "ERROR: multiple OWASP LLM lab ASGs found in $AWS_REGION; account cleanup is required." >&2
  printf "%s\n" "$ROWS" >&2
  exit 1
fi

printf "%s\n" "$ROWS"
