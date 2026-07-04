#!/bin/bash
# Clean up OWASP LLM lab runtime on the EC2 instance.
#
# 기본 모드:
#   - lab-* 컨테이너 stop/remove
#   - Quadlet .container 파일 제거
#   - generated systemd user unit reload
#   - 작업물과 모델 캐시는 보존
#
# 완전 정리:
#   sudo bash cleanup-lab.sh --purge
#   - 기본 정리에 더해 Ollama 모델, LLMGoat 모델/cache, fake-registry, embedding venv 제거

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "이 스크립트는 root 권한이 필요합니다."
  echo "  curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/cleanup-lab.sh | sudo bash"
  exit 1
fi

PURGE=false
if [ "${1:-}" = "--purge" ]; then
  PURGE=true
elif [ -n "${1:-}" ]; then
  echo "사용법: $0 [--purge]"
  exit 2
fi

LOG_FILE="${LAB_CLEANUP_LOG:-/var/log/owasp-llm-lab-cleanup.log}"
exec > >(tee -a "$LOG_FILE" | logger -t owasp-llm-cleanup) 2>&1

echo "=== owasp-llm-lab cleanup start: $(date -Iseconds) ==="
echo "PURGE=$PURGE"

if id ubuntu >/dev/null 2>&1; then
  UBUNTU_UID=$(id -u ubuntu)
  systemctl start "user@$UBUNTU_UID.service" >/dev/null 2>&1 || true

  runuser -u ubuntu -- env XDG_RUNTIME_DIR="/run/user/$UBUNTU_UID" bash <<'CLEANSH'
set -euo pipefail
units=(
  lab-ollama
  lab-day1-vuln-rag
  lab-day2-vuln-rag
  lab-day3-vuln-rag
  lab-day4-vuln-rag
  lab-day5-vuln-rag
  lab-day3-vuln-agent
  lab-llmgoat
  lab-day3-dvla
  lab-day2-fake-registry
  lab-vuln-rag
  lab-vuln-agent
  lab-dvla
  lab-fake-registry
)
for unit in "${units[@]}"; do
  systemctl --user stop "$unit.service" >/dev/null 2>&1 || true
  systemctl --user reset-failed "$unit.service" >/dev/null 2>&1 || true
done
for container in "${units[@]}"; do
  podman rm -f "$container" >/dev/null 2>&1 || true
done
systemctl --user daemon-reload || true
CLEANSH

  rm -f /home/ubuntu/.config/containers/systemd/lab-ollama.container
  rm -f /home/ubuntu/.config/containers/systemd/lab-day1-vuln-rag.container
  rm -f /home/ubuntu/.config/containers/systemd/lab-day2-vuln-rag.container
  rm -f /home/ubuntu/.config/containers/systemd/lab-day3-vuln-rag.container
  rm -f /home/ubuntu/.config/containers/systemd/lab-day4-vuln-rag.container
  rm -f /home/ubuntu/.config/containers/systemd/lab-day5-vuln-rag.container
  rm -f /home/ubuntu/.config/containers/systemd/lab-day3-vuln-agent.container
  rm -f /home/ubuntu/.config/containers/systemd/lab-day3-dvla.container
  rm -f /home/ubuntu/.config/containers/systemd/lab-day2-fake-registry.container
  rm -f /home/ubuntu/.config/containers/systemd/lab-vuln-rag.container
  rm -f /home/ubuntu/.config/containers/systemd/lab-vuln-agent.container
  rm -f /home/ubuntu/.config/containers/systemd/lab-llmgoat.container
  rm -f /home/ubuntu/.config/containers/systemd/lab-dvla.container
  rm -f /home/ubuntu/.config/containers/systemd/lab-fake-registry.container

  runuser -u ubuntu -- env XDG_RUNTIME_DIR="/run/user/$UBUNTU_UID" systemctl --user daemon-reload || true

  if [ "$PURGE" = true ]; then
    echo "Purging model/cache/generated lab data..."
    rm -rf /home/ubuntu/ollama-models
    rm -rf /home/ubuntu/.LLMGoat
    rm -rf /home/ubuntu/work/fake-registry
    rm -rf /home/ubuntu/work/embedding-venv
    install -d -m 0755 -o ubuntu -g ubuntu /home/ubuntu/work
  else
    echo "Preserved /home/ubuntu/work, /home/ubuntu/ollama-models, and /home/ubuntu/.LLMGoat"
  fi
else
  echo "ubuntu user not found; skipping user container cleanup"
fi

echo "=== owasp-llm-lab cleanup done: $(date -Iseconds) ==="
echo "Cleanup log: $LOG_FILE"
