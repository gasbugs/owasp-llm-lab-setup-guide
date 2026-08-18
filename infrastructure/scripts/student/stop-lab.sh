#!/bin/bash
# 수강생용 — ASG desired capacity를 0으로 내려 실습 인스턴스와 root EBS 삭제
set -euo pipefail

: "${AWS_PROFILE:?usage: AWS_PROFILE=<profile> AWS_REGION=<region> STUDENT=<id> bash stop-lab.sh}"
: "${AWS_REGION:=us-east-1}"
: "${STUDENT:?STUDENT 환경변수 필요}"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ASG_NAME=$(bash "$SCRIPT_DIR/asg-name.sh")

aws autoscaling update-auto-scaling-group \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --auto-scaling-group-name "$ASG_NAME" \
  --min-size 0 \
  --max-size 1 \
  --desired-capacity 0

echo "scaled to zero: $ASG_NAME"
echo "주의: 인스턴스와 root EBS가 삭제됩니다. 필요한 작업물은 먼저 GitHub 등 외부 저장소에 보존하세요."
echo "다음 start-lab.sh 실행 시 가용 용량이 있는 AZ에 새 인스턴스가 생성되며 public IP도 바뀝니다."
