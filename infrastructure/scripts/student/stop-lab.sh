#!/bin/bash
# Reuse the existing standalone EC2; never terminate or replace it.
set -euo pipefail

: "${AWS_PROFILE:?usage: AWS_PROFILE=<profile> AWS_REGION=<region> bash stop-lab.sh}"
: "${AWS_REGION:=us-east-1}"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
INSTANCE_ID=$(bash "$SCRIPT_DIR/instance-id.sh")

aws ec2 stop-instances \
  --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --instance-ids "$INSTANCE_ID"
aws ec2 wait instance-stopped \
  --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --instance-ids "$INSTANCE_ID"

echo "stopped: $INSTANCE_ID"
echo "root EBS와 모델·작업물은 보존됩니다. 중지 중에도 EBS 비용은 남습니다."
