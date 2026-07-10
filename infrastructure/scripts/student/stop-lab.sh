#!/bin/bash
# 수강생용 — 매일 종료 시 본인 인스턴스 stop (노트북에서 실행)
# EBS는 유지 → 내일 start-lab.sh로 작업 상태 복원. 이 구성은 EIP를 만들지 않아 public IP는 바뀔 수 있음
set -euo pipefail

: "${AWS_PROFILE:?usage: AWS_PROFILE=<profile> AWS_REGION=<region> STUDENT=<id> bash stop-lab.sh}"
: "${AWS_REGION:=us-east-1}"
: "${STUDENT:?STUDENT 환경변수 필요}"

if ! command -v aws >/dev/null 2>&1; then
  echo "ERROR: required command not found: aws" >&2
  echo "Install AWS CLI v2, then rerun stop-lab.sh." >&2
  exit 1
fi

if ! aws sts get-caller-identity --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "ERROR: AWS credentials are not ready for profile '$AWS_PROFILE' in region '$AWS_REGION'." >&2
  echo "Run one of the following, then retry:" >&2
  echo "  aws configure --profile $AWS_PROFILE" >&2
  echo "  aws sso login --profile $AWS_PROFILE" >&2
  exit 1
fi

ROWS=$(aws ec2 describe-instances --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --filters "Name=tag:Student,Values=$STUDENT" "Name=instance-state-name,Values=stopped,stopping,running,pending" \
  --query "Reservations[].Instances[].[InstanceId,State.Name]" --output text)

COUNT=$(printf "%s\n" "$ROWS" | awk 'NF { count++ } END { print count + 0 }')
if [ "$COUNT" -eq 0 ]; then
  echo "중지할 인스턴스가 없습니다. AWS_REGION/STUDENT 값을 확인하세요."
  exit 0
fi
if [ "$COUNT" -gt 1 ]; then
  echo "Student=$STUDENT 태그의 인스턴스가 여러 개입니다. 비용 사고 방지를 위해 자동 중지하지 않습니다."
  printf "%s\n" "$ROWS"
  exit 1
fi

ROW=$(printf "%s\n" "$ROWS" | awk 'NF { print; exit }')
IID=$(printf "%s" "$ROW" | awk '{ print $1 }')
STATE=$(printf "%s" "$ROW" | awk '{ print $2 }')

echo "instance: $IID ($STATE)"
case "$STATE" in
  stopped)
    echo "이미 stopped 상태입니다. EC2 시간당 요금은 발생하지 않습니다."
    ;;
  stopping)
    echo "이미 stopping 상태입니다. stopped 상태까지 기다립니다."
    aws ec2 wait instance-stopped --profile "$AWS_PROFILE" --region "$AWS_REGION" --instance-ids "$IID"
    ;;
  running|pending)
    echo "stopping: $IID"
    aws ec2 stop-instances --profile "$AWS_PROFILE" --region "$AWS_REGION" --instance-ids "$IID" >/dev/null
    aws ec2 wait instance-stopped --profile "$AWS_PROFILE" --region "$AWS_REGION" --instance-ids "$IID"
    ;;
  *)
    echo "지원하지 않는 인스턴스 상태: $STATE"
    exit 1
    ;;
esac
echo "stopped. EC2 시간당 요금은 멈췄습니다."
echo "주의: EBS 보존 비용은 계속 발생합니다. 강의 마지막 날에는 작업물을 백업한 뒤 terraform destroy -auto-approve로 EC2/EBS/VPC를 삭제하세요."
echo "참고: 이 구성은 EIP를 만들지 않으므로 stop/start 후 public IP는 바뀔 수 있습니다. SSM 접속은 Student 태그로 instance ID를 다시 조회하세요."
