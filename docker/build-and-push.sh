#!/bin/bash
# 강사 로컬 빌드 + Docker Hub push (Podman 사용)
#
# 사전조건:
#   - 본 머신에 podman 설치
#   - Docker Hub 계정 보유, 'podman login docker.io'로 로그인
#   - 환경변수 DOCKERHUB_NAMESPACE 설정 (Docker Hub 사용자명)
#
# 사용:
#   DOCKERHUB_NAMESPACE=your-username TAG=sha-<40자리-commit> ./build-and-push.sh
set -euo pipefail

cd "$(dirname "$0")"

: "${DOCKERHUB_NAMESPACE:?DOCKERHUB_NAMESPACE 환경변수 필요}"

: "${TAG:?TAG 환경변수 필요. 검증용은 sha-<40자리 Git commit> 사용}"
NS="$DOCKERHUB_NAMESPACE"

if [[ ! "$TAG" =~ ^sha-[0-9a-f]{40}$ ]] && [ "${ALLOW_NONIMMUTABLE_TAG:-false}" != "true" ]; then
  echo "ERROR: TAG는 sha-<40자리 lowercase Git commit> 형식이어야 합니다." >&2
  echo "  TAG=sha-\$(git rev-parse HEAD) 를 사용하세요." >&2
  echo "  로컬 진단용 예외는 ALLOW_NONIMMUTABLE_TAG=true를 명시하세요." >&2
  exit 2
fi

for name in base-gpu vuln-rag vuln-agent llmgoat dvla; do
  image="docker.io/$NS/owasp-llm-${name}:${TAG}"
  if podman manifest inspect "$image" >/dev/null 2>&1; then
    echo "ERROR: 기존 commit 태그를 덮어쓸 수 없습니다: $image" >&2
    echo "새 commit SHA 태그를 사용하세요." >&2
    exit 2
  fi
done

build_and_push() {
  local name="$1"
  local context="$2"
  local image="docker.io/$NS/owasp-llm-${name}:${TAG}"
  local extra_args=()
  if [ "$name" = "vuln-rag" ] || [ "$name" = "vuln-agent" ]; then
    extra_args=(--build-arg "BASE_IMAGE=docker.io/$NS/owasp-llm-base-gpu:${TAG}")
  fi
  echo "=== Building $image (context: $context) ==="
  if [ "${#extra_args[@]}" -gt 0 ]; then
    podman build --platform linux/amd64 "${extra_args[@]}" -t "$image" "$context"
  else
    podman build --platform linux/amd64 -t "$image" "$context"
  fi
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
echo "  -var \"image_tag=$TAG\""
echo "=========================================="
echo
echo "이미지 목록:"
podman images "docker.io/$NS/owasp-llm-*"
