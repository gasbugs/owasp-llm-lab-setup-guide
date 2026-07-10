#!/bin/bash
# 강사용 — 데모/dry-run 후 본인 인프라 destroy.
#
# ⚠️ 2026-05-20 운영 모델 재설계 이후: 수강생 자원은 *수강생 본인 AWS 계정*에 있어
# 강사가 destroy할 수 없습니다. 본 스크립트는 *강사 본인 dry-run* 자원 정리용.
#
# 수강생용 destroy는 docs/STUDENT-QUICKSTART.md 참고:
#   cd infrastructure/terraform && terraform destroy -auto-approve

set -euo pipefail

cd "$(dirname "$0")/../../terraform"

echo "=========================================="
echo "강사 dry-run 환경 destroy"
echo "=========================================="
echo
echo "현재 terraform state:"
if ! CURRENT_STATE=$(terraform state list); then
  echo "ERROR: terraform state를 읽지 못했습니다. 대상 확인 없이 destroy하지 않습니다." >&2
  exit 1
fi
if [ -z "$CURRENT_STATE" ]; then
  echo "ERROR: terraform state가 비어 있습니다. destroy할 관리 자원을 확인할 수 없어 중단합니다." >&2
  exit 1
fi
printf '%s\n' "$CURRENT_STATE"
echo
read -rp "위 자원을 모두 destroy합니까? (yes/no) " ANS
[ "$ANS" = "yes" ] || { echo "취소"; exit 0; }

terraform destroy -auto-approve

if ! REMAINING_STATE=$(terraform state list); then
  echo "ERROR: destroy 후 terraform state를 읽지 못했습니다. 정리 완료로 간주하지 않습니다." >&2
  exit 1
fi
if [ -n "$REMAINING_STATE" ]; then
  echo "ERROR: destroy 후에도 다음 관리 자원이 state에 남아 있습니다:" >&2
  printf '%s\n' "$REMAINING_STATE" >&2
  exit 1
fi

echo
echo "=========================================="
echo "Destroy 완료. Terraform state가 비어 있음을 확인했습니다."
echo "이 stack의 EC2/EBS/VPC 등 관리 자원은 삭제됐습니다. 이미 발생한 요금과 외부 관리 자원은 별도로 확인하세요."
echo "=========================================="
