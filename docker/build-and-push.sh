#!/bin/bash
# 강사 로컬 빌드 + GitHub Container Registry push (Podman 사용)
#
# 사전조건:
#   - 본 머신에 podman 설치
#   - GitHub Packages write 권한이 있는 토큰으로 'podman login ghcr.io' 완료
#   - 환경변수 IMAGE_NAMESPACE 설정 (GitHub 사용자명 또는 organization)
#
# 사용:
#   IMAGE_NAMESPACE=your-namespace TAG=sha-<40자리-commit> ./build-and-push.sh
set -euo pipefail

cd "$(dirname "$0")"

: "${IMAGE_NAMESPACE:?IMAGE_NAMESPACE 환경변수 필요}"

: "${TAG:?TAG 환경변수 필요. 검증용은 sha-<40자리 Git commit> 사용}"
NS="$IMAGE_NAMESPACE"

if [[ ! "$TAG" =~ ^sha-[0-9a-f]{40}$ ]] && [ "${ALLOW_NONIMMUTABLE_TAG:-false}" != "true" ]; then
  echo "ERROR: TAG는 sha-<40자리 lowercase Git commit> 형식이어야 합니다." >&2
  echo "  TAG=sha-\$(git rev-parse HEAD) 를 사용하세요." >&2
  echo "  로컬 진단용 예외는 ALLOW_NONIMMUTABLE_TAG=true를 명시하세요." >&2
  exit 2
fi

for name in base-gpu vuln-rag vuln-agent llmgoat dvla; do
  image="ghcr.io/$NS/owasp-llm-${name}:${TAG}"
  inspect_output="$(mktemp)"
  if podman manifest inspect "$image" >"$inspect_output" 2>&1; then
    rm -f "$inspect_output"
    echo "ERROR: 기존 commit 태그를 덮어쓸 수 없습니다: $image" >&2
    echo "새 commit SHA 태그를 사용하세요." >&2
    exit 2
  else
    inspect_text="$(cat "$inspect_output")"
    rm -f "$inspect_output"
    case "$inspect_text" in
      *"manifest unknown"*|*"name unknown"*)
        echo "confirmed absent: $image"
        ;;
      *)
        echo "ERROR: registry 조회가 정상적인 not-found로 끝나지 않았습니다: $image" >&2
        echo "$inspect_text" >&2
        exit 3
        ;;
    esac
  fi
done

build_and_push() {
  local name="$1"
  local context="$2"
  local image="ghcr.io/$NS/owasp-llm-${name}:${TAG}"
  local extra_args=(--build-arg "VCS_REF=${TAG#sha-}")
  if [ "$name" = "vuln-rag" ] || [ "$name" = "vuln-agent" ]; then
    extra_args+=(--build-arg "BASE_IMAGE=ghcr.io/$NS/owasp-llm-base-gpu:${TAG}")
  fi
  echo "=== Building $image (context: $context) ==="
  podman build --platform linux/amd64 "${extra_args[@]}" -t "$image" "$context"
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
echo "  -var \"image_namespace=$NS\""
echo "  -var \"image_tag=$TAG\""
echo "=========================================="
echo
echo "이미지 목록:"
podman images "ghcr.io/$NS/owasp-llm-*"
