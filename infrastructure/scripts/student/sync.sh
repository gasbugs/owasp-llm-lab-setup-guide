#!/bin/bash
# Compatibility helper — 현재 운영 모델에서는 별도 원격 동기화를 자동 수행하지 않는다.
# 작업물 보존:
#   - EBS 자동 보존: stop/start 시 어제 상태 그대로 유지
#   - 영구 보존: 본인 GitHub 작업 repo에 git push
#
# 사용법 (인스턴스 안):
#   cd ~/work
#   git init -q && git add . && git commit -m "Day-$(date +%u) $(date +%F)" || true
#   GITHUB_ID="your-github-id"
#   git remote add origin "https://github.com/${GITHUB_ID}/owasp-llm-work.git"
#   git push origin main
echo "자동 동기화는 수행하지 않습니다. README 또는 day1/03-lab-environment-setup.md Step 7을 참고하세요."
echo "작업물 영구 보존은 본인 GitHub 작업 repo에 git push."
