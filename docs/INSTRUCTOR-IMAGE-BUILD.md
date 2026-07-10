# Instructor image build and release

이 문서는 강사 또는 운영자가 실습 컨테이너 이미지를 commit과 연결해 빌드하고 공개 GitHub Container Registry(GHCR)에 배포하는 절차입니다. 실제 EC2 검증에서는 `latest`가 아니라 `sha-<40자리 commit>` 태그와 resolved digest를 함께 사용합니다. 일부 upstream base가 이동 태그이므로 bit-for-bit 재빌드를 주장하지 않으며, 최초 publish된 commit 태그는 덮어쓰지 않습니다.

## 이미지 세트

| 이미지 | Dockerfile |
|---|---|
| `owasp-llm-base-gpu` | `docker/base-gpu/Dockerfile` |
| `owasp-llm-vuln-rag` | `docker/vuln-rag/Dockerfile` |
| `owasp-llm-vuln-agent` | `docker/vuln-agent/Dockerfile` |
| `owasp-llm-llmgoat` | `docker/llmgoat/Dockerfile` |
| `owasp-llm-dvla` | `docker/dvla/Dockerfile` |

## GitHub Actions release

`.github/workflows/build-and-push.yaml`은 다음 순서를 강제합니다.

1. unit·repository hygiene·Python compile·전체 shell syntax·Terraform·Packer·Docker build configuration 검증
2. 다섯 이미지를 `sha-${{ github.sha }}` 태그로 빌드·push
3. 전체 이미지가 성공한 뒤 SHA manifest를 `latest`로 승격

중간 이미지가 실패하면 `latest` 승격 단계는 실행되지 않습니다. `vuln-rag`와 `vuln-agent`도 같은 커밋의 SHA-tagged `base-gpu`를 부모로 사용합니다.
같은 commit 태그가 하나라도 이미 존재하면 workflow는 빌드 전에 실패합니다. 부분 publish가 발생한 경우 기존 태그를 덮어쓰지 말고 원인을 수정한 새 commit으로 다시 실행합니다.

Workflow는 `github.actor`와 저장소에 자동 발급되는 `GITHUB_TOKEN`을 사용하므로 별도 registry 계정이나 외부 secret을 등록하지 않습니다. `build`와 `promote-latest` job에만 `packages: write`가 부여됩니다. 각 Dockerfile의 `org.opencontainers.image.source` label이 package를 이 공개 저장소와 연결합니다.

최초 publish 뒤 다섯 package의 visibility를 GitHub package 설정에서 모두 `Public`으로 확인합니다. EC2와 Packer는 registry 자격증명을 받지 않으므로, 아래 anonymous manifest 조회가 다섯 이미지 모두에서 성공하기 전에는 라이브 검증을 시작하지 않습니다.

```bash
SETUP_COMMIT=$(git rev-parse HEAD)
for image in base-gpu vuln-rag vuln-agent llmgoat dvla; do
  podman manifest inspect \
    "ghcr.io/gasbugs/owasp-llm-${image}:sha-${SETUP_COMMIT}" >/dev/null
done
```

## 로컬 수동 빌드

CI 장애 조사나 개인 namespace 검증에는 Podman helper를 사용할 수 있습니다.

사전 조건:

- Podman
- `write:packages` 권한의 GitHub personal access token으로 `podman login ghcr.io`
- Linux/amd64 builder 또는 Podman machine

```bash
SETUP_COMMIT=$(git rev-parse HEAD)
cd docker
IMAGE_NAMESPACE=your-github-id \
TAG="sha-$SETUP_COMMIT" \
  ./build-and-push.sh
```

수동 helper는 지정 태그만 push하며 CI의 최종 `latest` 승격을 대신하지 않습니다.

## EC2 pull 확인

```bash
git fetch origin main
SETUP_COMMIT=$(git rev-parse origin/main)
for image in base-gpu vuln-rag vuln-agent llmgoat dvla; do
  sudo -u ubuntu podman pull \
    "ghcr.io/gasbugs/owasp-llm-${image}:sha-${SETUP_COMMIT}"
done
```

이후 [`LIVE-VALIDATION.md`](LIVE-VALIDATION.md)의 설치와 e2e 절차로 이미지 세트 전체를 검증합니다.

## 주의

- 이미지는 의도적으로 취약한 교육용 앱입니다.
- public registry 설명에 교육용 취약 앱임을 명시합니다.
- `IMAGE_NAMESPACE`, `IMAGE_TAG`와 검증 증거에 기록한 값이 정확히 일치해야 합니다.
- `latest`만으로 검증 결과를 기록하지 않습니다. 같은 이름이 다음 release에서 이동하기 때문입니다.
