# 컨테이너 이미지 — Podman 기반 일관성 보장

본 디렉터리는 강의 실습용 컨테이너 이미지의 정의입니다.

- **런타임**: Podman (rootless) — `docker compose`와 호환되는 `podman compose` 사용
- **레지스트리**: Docker Hub (`docker.io/<DOCKERHUB_NAMESPACE>/...`)
- **빌드**: 강사 로컬 머신에서 `build-and-push.sh` 실행 → Hub로 push
- **사용**: AMI 빌드 시 podman pull로 사전 캐시 → 강의 EC2는 인터넷 없이도 즉시 기동

## 이미지 구성

| 이미지 | 역할 | 사용 Day |
|---|---|---|
| `owasp-llm-base-gpu` | CUDA 12.5 + Python 3.12 + uv (FROM 베이스) | 모든 Day |
| `owasp-llm-vuln-rag` | 일부러 취약한 RAG 챗봇 (FastAPI + Ollama 연동) | Day 1/2/4/5 |
| `owasp-llm-vuln-agent` | Function calling 기반 취약 에이전트 | Day 3 |
| (외부) `ollama/ollama` | 모델 호스팅 | 모든 Day |
| (외부) `chromadb/chroma` | 벡터 DB | Day 2/4 |
| (외부) `ghcr.io/open-webui/open-webui` | 웹 UI | 모든 Day |
| (외부) `langfuse/langfuse` | 관찰성 데모 | Day 5 |

`vuln-rag`는 하나의 앱에서 `day1` ~ `day5` 시나리오를 모두 제공합니다. UI의 Scenario 선택 메뉴나 `/api/chat` 요청 body의 `scenario` 값으로 시나리오를 선택합니다.

## 빌드·푸시 흐름 (강사)

### 사전 준비
- 로컬에 Podman 설치 (`brew install podman` 등)
- Docker Hub 계정, `podman login docker.io`로 로그인
- 환경변수 `DOCKERHUB_NAMESPACE` 설정 (예: `owasplllab`)

### 빌드 + 푸시
```bash
cd docker
DOCKERHUB_NAMESPACE=your-username ./build-and-push.sh
```

스크립트가 다음 순서로 처리:
1. `base-gpu` 빌드·푸시 (vuln-* 이미지의 FROM)
2. `vuln-rag` 빌드·푸시 (base-gpu 참조)
3. `vuln-agent` 빌드·푸시 (base-gpu 참조)

`--platform linux/amd64` 옵션으로 강사 머신이 Apple Silicon이어도 x86_64 이미지로 빌드.

## 강의 EC2 (Podman rootless) — 한눈에

수강생 인스턴스 안에서:
```bash
# /etc/lab/env가 DOCKERHUB_NAMESPACE를 포함
cd ~/owasp-top-10-for-llm/docker
sudo -u ubuntu podman run -d --replace --name lab-day1-vuln-rag \
  --network host -e DEFAULT_SCENARIO=day1 \
  -e OLLAMA_URL=http://localhost:11434 \
  -e OLLAMA_MODEL=llama3.1:8b-instruct-q4_K_M \
  docker.io/gasbugs/owasp-llm-vuln-rag:latest
podman compose ps
sudo -u ubuntu podman logs -f lab-day1-vuln-rag
```

핵심 차이점 (docker → podman rootless):

| 항목 | Docker | Podman rootless (본 강의) |
|---|---|---|
| daemon | systemd `docker.service` | daemonless, 사용자 프로세스로 직접 |
| 권한 | sudo 또는 docker group | 일반 사용자(ubuntu) 직접 |
| GPU 노출 | `--gpus all` | `--device nvidia.com/gpu=all` (CDI) |
| 네트워크 | docker0 bridge | slirp4netns 또는 pasta |
| 볼륨 SELinux | `:Z` 무관 | `:Z` 권장 (cgroup label) |
| compose | `docker compose` | `podman compose` (CLI 호환) |

## podman compose 호환성 메모

- `services.*.image` — 그대로
- `services.*.profiles` — 지원됨
- `services.*.healthcheck` — 지원됨
- `services.*.deploy.resources.reservations.devices` (Docker 형식) — Podman은 무시. **대신 `devices:` 키로 CDI device 명시** — 본 compose에 이미 적용됨
- `services.*.depends_on.<svc>.condition` — Podman 4.7+ 지원

## 보안 표시

`vuln-*` 이미지는 모두 라벨:
```dockerfile
LABEL org.opencontainers.image.title="owasp-llm-vuln-..."
LABEL owasp.llm.lab.warning="INTENTIONALLY VULNERABLE — DO NOT DEPLOY OUTSIDE TRAINING"
```

수강생용 안내: `podman ps`에 `lab-day*-vuln-*`이 보이면 의도적 취약 컨테이너임을 항상 인지.

## 트러블슈팅

**`podman compose: command not found`**: `apt install podman-compose` (Ubuntu) 또는 podman 4.7+ 의 `compose` 플러그인. AMI 빌드에 포함됨.

**GPU 접근 실패**: `/etc/cdi/nvidia.yaml`이 존재해야. `sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml` 재실행.

**rootless에서 11434 포트 바인딩 실패**: 기본적으로 < 1024는 안 됨. 본 강의는 11434/8080/8000~8013/5000/8501로 1024+. 문제 없음.

**push 거부**: `podman login docker.io` 다시. `~/.config/containers/auth.json`에 토큰 저장됨.
