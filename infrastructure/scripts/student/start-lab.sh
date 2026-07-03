#!/bin/bash
# 학생용 — 매일 아침 본인 인스턴스 시작 (노트북에서 실행)
# 새 모델 (2026-05-20): aws ec2 start-instances로 본인 EC2 켜기
set -euo pipefail

: "${AWS_PROFILE:?usage: AWS_PROFILE=<profile> AWS_REGION=<region> STUDENT=<id> bash start-lab.sh}"
: "${AWS_REGION:=us-east-1}"
: "${STUDENT:?STUDENT 환경변수 필요 — 본인 student-id}"

if ! command -v aws >/dev/null 2>&1; then
  echo "ERROR: required command not found: aws" >&2
  echo "Install AWS CLI v2, then rerun start-lab.sh." >&2
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
  echo "본인 인스턴스 없음. AWS_REGION/STUDENT 값을 확인하거나 terraform apply를 먼저 실행하세요."
  exit 1
fi
if [ "$COUNT" -gt 1 ]; then
  echo "Student=$STUDENT 태그의 인스턴스가 여러 개입니다. AWS 콘솔에서 중복 리소스를 정리한 뒤 다시 실행하세요."
  printf "%s\n" "$ROWS"
  exit 1
fi

ROW=$(printf "%s\n" "$ROWS" | awk 'NF { print; exit }')
IID=$(printf "%s" "$ROW" | awk '{ print $1 }')
STATE=$(printf "%s" "$ROW" | awk '{ print $2 }')

echo "instance: $IID ($STATE)"
case "$STATE" in
  running)
    echo "이미 running 상태입니다. SSM 접속 명령을 바로 사용하세요."
    ;;
  pending)
    echo "이미 시작 중입니다. running 상태까지 기다립니다."
    aws ec2 wait instance-running --profile "$AWS_PROFILE" --region "$AWS_REGION" --instance-ids "$IID"
    ;;
  stopped)
    aws ec2 start-instances --profile "$AWS_PROFILE" --region "$AWS_REGION" --instance-ids "$IID" >/dev/null
    echo "starting... (1~2분 후 SSM 접속 가능)"
    aws ec2 wait instance-running --profile "$AWS_PROFILE" --region "$AWS_REGION" --instance-ids "$IID"
    ;;
  stopping)
    echo "현재 stopping 상태입니다. stopped가 된 뒤 다시 시작합니다."
    aws ec2 wait instance-stopped --profile "$AWS_PROFILE" --region "$AWS_REGION" --instance-ids "$IID"
    aws ec2 start-instances --profile "$AWS_PROFILE" --region "$AWS_REGION" --instance-ids "$IID" >/dev/null
    aws ec2 wait instance-running --profile "$AWS_PROFILE" --region "$AWS_REGION" --instance-ids "$IID"
    ;;
  *)
    echo "지원하지 않는 인스턴스 상태: $STATE"
    exit 1
    ;;
esac
echo "running. SSM 접속:"
echo "  aws ssm start-session --profile $AWS_PROFILE --region $AWS_REGION --target $IID"
echo "다른 터미널에서 INSTANCE_ID가 필요하면:"
echo "  export INSTANCE_ID=\$(AWS_PROFILE=$AWS_PROFILE AWS_REGION=$AWS_REGION STUDENT=$STUDENT bash infrastructure/scripts/student/instance-id.sh)"
