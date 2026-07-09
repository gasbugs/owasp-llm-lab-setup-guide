#!/bin/bash
# 강사용 — 데모/dry-run 후 본인 인프라 destroy.
#
# ⚠️ 2026-05-20 운영 모델 재설계 이후: 수강생 자원은 *수강생 본인 AWS 계정*에 있어
# 강사가 destroy할 수 없습니다. 본 스크립트는 *강사 본인 dry-run* 자원 정리용.
#
# 수강생용 destroy는 STUDENT_SETUP.md 12단계 참고:
#   cd infrastructure/terraform && terraform destroy -auto-approve

set -euo pipefail

cd "$(dirname "$0")/../../terraform"

echo "=========================================="
echo "강사 dry-run 환경 destroy"
echo "=========================================="
echo
echo "현재 terraform state:"
terraform state list 2>/dev/null | head -20 || echo "  (state 없음)"
echo
read -rp "위 자원을 모두 destroy합니까? (yes/no) " ANS
[ "$ANS" = "yes" ] || { echo "취소"; exit 0; }

terraform destroy -auto-approve

echo
echo "=========================================="
echo "Destroy 완료. 비용 0/h."
echo "S3 백업 / VPC Endpoint 등 부수 자원 없음 (PR #6 이후 단순 설계)."
echo "=========================================="
