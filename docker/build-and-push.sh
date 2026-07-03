#!/bin/bash
# 강사 로컬 빌드 + Docker Hub push (Podman 사용)
#
# 사전조건:
#   - 본 머신에 podman 설치
#   - Docker Hub 계정 보유, 'podman login docker.io'로 로그인
#   - 환경변수 DOCKERHUB_NAMESPACE 설정 (Docker Hub 사용자명)
#
# 사용:
#   DOCKERHUB_NAMESPACE=your-username ./build-and-push.sh
set -euo pipefail

cd "$(dirname "$0")"

: "${DOCKERHUB_NAMESPACE:?DOCKERHUB_NAMESPACE 환경변수 필요}"

TAG="${TAG:-latest}"
NS="$DOCKERHUB_NAMESPACE"

build_and_push() {
  local name="$1"
  local context="$2"
  local image="docker.io/$NS/owasp-llm-${name}:${TAG}"
  local extra_args=""
  if [ "$name" != "base-gpu" ]; then
    extra_args="--build-arg BASE_IMAGE=docker.io/$NS/owasp-llm-base-gpu:${TAG}"
  fi
  echo "=== Building $image (context: $context) ==="
  podman build --platform linux/amd64 $extra_args -t "$image" "$context"
  echo "=== Pushing $image ==="
  podman push "$image"
}

# base-gpu가 vuln-rag/vuln-agent의 FROM 이미지라 먼저 빌드 + push
build_and_push "base-gpu"    "./base-gpu"

build_and_push "vuln-rag"    "./vuln-rag"
build_and_push "vuln-agent"  "./vuln-agent"
build_and_push "llmgoat"     "./llmgoat"
build_and_push "dvla"        "./dvla"

echo
echo "=========================================="
echo "Push 완료. Packer 빌드에서 다음 변수로 사용:"
echo "  -var \"dockerhub_namespace=$NS\""
echo "=========================================="
echo
echo "이미지 목록:"
podman images "docker.io/$NS/owasp-llm-*"
