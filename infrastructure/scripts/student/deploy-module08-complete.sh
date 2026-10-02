#!/usr/bin/env bash
set -euo pipefail

# Compatibility tombstone: the former GPU deployment deleted learner volumes.
# Do not source credentials, create AWS resources or change running containers.
printf '%s\n' \
  '이 일괄 배포 명령은 폐기되었습니다. 어떤 자원도 변경하지 않았습니다.' \
  '현재 구성은 GPU 없는 WSL에서 Bedrock Gateway와 Nova Lite를 사용합니다.' \
  '단계별 조립: docs/GUARDRAILS-SETUP.md' \
  '관측 스택 연결: examples/security-monitoring/README.md' >&2
exit 2
