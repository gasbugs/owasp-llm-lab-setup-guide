#!/bin/bash
# 강의용 컨테이너 이미지 사전 pull + 모델 weights 다운로드
# (Podman rootless로 ubuntu 사용자가 실행)
set -euo pipefail

: "${DEFAULT_MODEL:?DEFAULT_MODEL 환경변수 필요}"
: "${DOCKERHUB_NAMESPACE:?DOCKERHUB_NAMESPACE 환경변수 필요. 예: owasplllab}"

# 1) Docker Hub 공개 이미지 + 강의 이미지 pull (rootless)
sudo -u ubuntu -i podman pull docker.io/ollama/ollama:latest
sudo -u ubuntu -i podman pull docker.io/library/chromadb-chroma:latest || \
  sudo -u ubuntu -i podman pull docker.io/chromadb/chroma:latest
sudo -u ubuntu -i podman pull docker.io/ghcr.io/open-webui/open-webui:main || \
  sudo -u ubuntu -i podman pull ghcr.io/open-webui/open-webui:main
sudo -u ubuntu -i podman pull docker.io/langfuse/langfuse:2 || true
sudo -u ubuntu -i podman pull docker.io/library/postgres:16

# 강사가 미리 Docker Hub에 push해 둔 강의 컨테이너 이미지
sudo -u ubuntu -i podman pull "docker.io/${DOCKERHUB_NAMESPACE}/owasp-llm-base-gpu:latest" || \
  echo "(base-gpu 이미지가 아직 push 안 됨 — 강사가 docker/push-to-hub.sh 실행 필요)"
sudo -u ubuntu -i podman pull "docker.io/${DOCKERHUB_NAMESPACE}/owasp-llm-vuln-rag:latest" || true
sudo -u ubuntu -i podman pull "docker.io/${DOCKERHUB_NAMESPACE}/owasp-llm-vuln-agent:latest" || true

# 2) 모델 weights 사전 다운로드 — Ollama를 잠깐 띄워 pull한 다음 종료
# weights는 /home/ubuntu/.local/share/containers/storage/volumes 또는 별도 호스트 디렉터리에 보존
sudo mkdir -p /home/ubuntu/ollama-models
sudo chown -R ubuntu:ubuntu /home/ubuntu/ollama-models

sudo -u ubuntu -i podman run --rm -d \
  --name ollama-prepull \
  --device nvidia.com/gpu=all \
  -v /home/ubuntu/ollama-models:/root/.ollama:Z \
  -p 11434:11434 \
  docker.io/ollama/ollama:latest

# Ollama listening 대기
for i in $(seq 1 60); do
  if sudo -u ubuntu -i podman exec ollama-prepull ollama --version >/dev/null 2>&1; then break; fi
  sleep 2
done

sudo -u ubuntu -i podman exec ollama-prepull ollama pull "$DEFAULT_MODEL"
sudo -u ubuntu -i podman stop ollama-prepull

# 3) 정리
sudo -u ubuntu -i podman system prune -af --filter "label!=keep" || true
sudo apt-get clean

# 4) AMI 빌드 메타데이터
sudo mkdir -p /etc/lab
sudo tee /etc/lab/build-info <<EOF
AMI_BUILD_TIME=$(date -Iseconds)
DEFAULT_MODEL=$DEFAULT_MODEL
DOCKERHUB_NAMESPACE=$DOCKERHUB_NAMESPACE
EOF

echo "=== 40-pull-images.sh done ==="
df -h /
sudo -u ubuntu -i podman images
