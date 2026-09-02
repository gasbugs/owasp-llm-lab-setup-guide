#!/bin/bash
# 강의용 컨테이너 이미지 사전 pull + 모델 weights 다운로드
# (일반 Docker daemon을 ubuntu 사용자가 docker 그룹 권한으로 실행)
set -euo pipefail

: "${DEFAULT_MODEL:?DEFAULT_MODEL 환경변수 필요}"
: "${IMAGE_NAMESPACE:?IMAGE_NAMESPACE 환경변수 필요. 예: gasbugs}"
: "${IMAGE_TAG:?IMAGE_TAG 환경변수 필요. sha-<40자리 lowercase Git commit> 필수}"

if [[ ! "$IMAGE_TAG" =~ ^sha-[0-9a-f]{40}$ ]]; then
  echo "ERROR: IMAGE_TAG must match sha-<40 lowercase Git commit characters>." >&2
  exit 2
fi

# 1) 실제 Compose 런타임 이미지 pull
sudo -u ubuntu -i docker pull docker.io/ollama/ollama:latest
sudo -u ubuntu -i docker pull docker.io/library/python:3.12-slim

# 동일 커밋의 이미지 세트가 하나라도 없으면 AMI 빌드를 실패시킨다.
for image in base-gpu vuln-rag vuln-agent llmgoat dvla; do
  sudo -u ubuntu -i docker pull \
    "ghcr.io/${IMAGE_NAMESPACE}/owasp-llm-${image}:${IMAGE_TAG}"
done

# 2) 모델 weights 사전 다운로드 — Ollama를 잠깐 띄워 pull한 다음 종료
# weights는 명시적인 host 디렉터리에 보존한다.
sudo mkdir -p /home/ubuntu/ollama-models
sudo chown -R ubuntu:ubuntu /home/ubuntu/ollama-models

sudo -u ubuntu -i docker run --rm -d \
  --name ollama-prepull \
  --gpus all \
  -v /home/ubuntu/ollama-models:/root/.ollama \
  -p 11434:11434 \
  docker.io/ollama/ollama:latest

# Ollama listening 대기
for i in $(seq 1 60); do
  if sudo -u ubuntu -i docker exec ollama-prepull ollama --version >/dev/null 2>&1; then break; fi
  sleep 2
done

sudo -u ubuntu -i docker exec ollama-prepull ollama pull "$DEFAULT_MODEL"
sudo -u ubuntu -i docker stop ollama-prepull

# 3) 중지된 임시 컨테이너만 정리한다. 사전 pull 이미지는 AMI cache로 보존한다.
sudo -u ubuntu -i docker container prune -f || true
sudo apt-get clean

# 4) AMI 빌드 메타데이터
sudo mkdir -p /etc/lab
sudo tee /etc/lab/build-info <<EOF
AMI_BUILD_TIME=$(date -Iseconds)
DEFAULT_MODEL=$DEFAULT_MODEL
IMAGE_NAMESPACE=$IMAGE_NAMESPACE
IMAGE_TAG=$IMAGE_TAG
EOF

echo "=== 40-pull-images.sh done ==="
df -h /
sudo -u ubuntu -i docker images
