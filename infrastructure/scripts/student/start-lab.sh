#!/bin/bash
# Reuse the existing standalone EC2; never terminate or replace it.
set -euo pipefail

: "${AWS_PROFILE:?usage: AWS_PROFILE=<profile> AWS_REGION=<region> bash start-lab.sh}"
: "${AWS_REGION:=us-east-1}"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
INSTANCE_ID=$(bash "$SCRIPT_DIR/instance-id.sh")

aws ec2 start-instances \
  --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --instance-ids "$INSTANCE_ID"
aws ec2 wait instance-running \
  --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --instance-ids "$INSTANCE_ID"

echo "running: $INSTANCE_ID"
echo "재시작 뒤 공인 IP가 바뀔 수 있으므로 브라우저 접속 주소를 다시 조회하세요."
echo "  aws ssm start-session --profile $AWS_PROFILE --region $AWS_REGION --target $INSTANCE_ID"
