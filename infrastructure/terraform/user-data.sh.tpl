#!/bin/bash
# Optional user-data bootstrap.
#
# 기본 Terraform 설정에서는 실행되지 않는다.
# `enable_user_data_bootstrap = true`로 명시한 경우에만 최초 부팅 시
# 학생용 수동 설치 스크립트와 동일한 install-lab.sh를 내려받아 실행한다.

set -euo pipefail
exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1

RAW_URL="${lab_setup_repo_raw_url}"
INSTALL_SCRIPT="/tmp/owasp-llm-install-lab.sh"

echo "=== optional user-data bootstrap start: $(date -Iseconds) ==="
echo "Install script source: $RAW_URL/infrastructure/scripts/student/install-lab.sh"

curl -fsSL "$RAW_URL/infrastructure/scripts/student/install-lab.sh" -o "$INSTALL_SCRIPT"
chmod 0755 "$INSTALL_SCRIPT"

LAB_SETUP_REPO_RAW_URL="$RAW_URL" bash "$INSTALL_SCRIPT"

echo "=== optional user-data bootstrap done: $(date -Iseconds) ==="
