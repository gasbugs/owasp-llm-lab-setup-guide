#!/bin/bash
# 수강생용 — ASG desired capacity를 1로 올려 새 실습 인스턴스 생성
set -euo pipefail

: "${AWS_PROFILE:?usage: AWS_PROFILE=<profile> AWS_REGION=<region> STUDENT=<id> bash start-lab.sh}"
: "${AWS_REGION:=us-east-1}"
: "${STUDENT:?STUDENT 환경변수 필요 — 본인 student-id}"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ASG_NAME=$(bash "$SCRIPT_DIR/asg-name.sh")

aws autoscaling update-auto-scaling-group \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --auto-scaling-group-name "$ASG_NAME" \
  --min-size 0 \
  --max-size 1 \
  --desired-capacity 1

echo "creating a new instance in an available AZ: $ASG_NAME"
INSTANCE_ID=""
for _ in $(seq 1 120); do
  INSTANCE_ID=$(aws ec2 describe-instances \
    --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" \
    --filters "Name=tag:Student,Values=$STUDENT" "Name=instance-state-name,Values=pending,running" \
    --query 'Reservations[0].Instances[0].InstanceId' \
    --output text 2>/dev/null || true)
  if [[ "$INSTANCE_ID" == i-* ]]; then
    break
  fi
  sleep 5
done

if [[ "$INSTANCE_ID" != i-* ]]; then
  echo "ERROR: ASG가 10분 안에 인스턴스를 만들지 못했습니다. ASG Activity에서 용량 부족 원인을 확인하세요." >&2
  exit 1
fi

aws ec2 wait instance-running \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --instance-ids "$INSTANCE_ID"

echo "running: $INSTANCE_ID"
echo "SSM 접속:"
echo "  aws ssm start-session --profile $AWS_PROFILE --region $AWS_REGION --target $INSTANCE_ID"
