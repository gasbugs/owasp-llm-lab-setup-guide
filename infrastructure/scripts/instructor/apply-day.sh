#!/bin/bash
# 강사용 — D-1 dry-run 본인 환경 apply.
#
# ⚠️ 2026-05-20 운영 모델 재설계 이후: 수강생 자원은 *수강생 본인 AWS 계정*에 있어
# 강사가 apply할 수 없습니다. 본 스크립트는 *강사 dry-run/검증* 자원 생성용.
# 수강생용 apply 경로는 STUDENT_SETUP.md 8단계 참고.
set -euo pipefail

cd "$(dirname "$0")/../../terraform"

if [ ! -f terraform.tfvars ]; then
  echo "ERROR: terraform.tfvars가 없습니다. terraform.tfvars.example을 복사해 채우세요."
  exit 1
fi

terraform init -upgrade
terraform plan -out tfplan
echo
read -rp "위 plan으로 apply할까요? (yes/no) " ANS
if [ "$ANS" != "yes" ]; then
  echo "취소됨."
  rm tfplan
  exit 0
fi

terraform apply tfplan
rm tfplan

echo
echo "=========================================="
echo "Apply 완료. 인스턴스는 *부팅 후 stopped 상태가 아닌, running 상태*입니다."
echo "필요 시 즉시 stop: aws ec2 stop-instances --instance-ids \$(terraform output -raw instance_ids)"
echo
echo "SSM 접속 명령:"
terraform output -json ssm_session_commands 2>/dev/null | jq . || echo "  (jq 없음 — terraform output ssm_session_commands)"
echo "=========================================="
