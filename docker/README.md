# Runtime container images

`docker/`는 EC2 실습 런타임의 이미지 정의입니다. 배포의 단일 기준은 `infrastructure/scripts/student/install-lab.sh`가 생성하는 Podman rootless Quadlet unit입니다. 이전의 단일 시나리오 Compose 구성은 고정 포트 동시 실행 계약과 충돌하여 제거했습니다.

## 이미지 세트

| 이미지 | 역할 | 실행 위치 |
|---|---|---|
| `owasp-llm-base-gpu` | CUDA 12.8, Python 3.12, uv 부모 이미지 | 빌드 기반 |
| `owasp-llm-vuln-rag` | Day 1~5 시나리오를 제공하는 취약 RAG 앱 | 8000, 8010~8013 |
| `owasp-llm-vuln-agent` | LLM06 tool-calling 취약 Agent | 8001 |
| `owasp-llm-llmgoat` | cross-platform 챌린지 UI | 5000 |
| `owasp-llm-dvla` | 고정 upstream commit의 ReAct Agent 앱 | 8501 |
| `ollama/ollama` | 공용 로컬 모델 API | 11434 |
| `python:3.12-slim` | Portal과 fake registry의 경량 런타임 | 8080, 8002 |

설치 스크립트는 같은 `vuln-rag` 이미지를 다섯 Quadlet unit으로 동시에 실행하며 `DEFAULT_SCENARIO`, `PORT`, uvicorn `Exec`를 함께 고정합니다.

| 컨테이너 | scenario | 포트 |
|---|---|---:|
| `lab-day1-vuln-rag` | day1 / LLM01 | 8000 |
| `lab-day2-vuln-rag` | day2 / LLM02·LLM04 | 8010 |
| `lab-day3-vuln-rag` | day3 / LLM05 | 8011 |
| `lab-day4-vuln-rag` | day4 / LLM07·LLM09, Day 2 LLM08 공유 | 8012 |
| `lab-day5-vuln-rag` | day5 / LLM10 | 8013 |

`/healthz`는 `default_scenario`와 전체 `scenarios` 목록을 반환합니다. 이미지 HEALTHCHECK도 `PORT`를 사용하므로 실제 uvicorn 포트와 일치합니다.

## 빌드와 commit 태그

정식 publish는 [GitHub Actions workflow](../.github/workflows/build-and-push.yaml)가 담당합니다. 품질 게이트 후 전체 이미지를 `sha-<40자리 commit>`으로 push하고, 이미지 세트가 모두 성공한 뒤에만 `latest`로 승격합니다.

commit 태그는 최초 publish 뒤 덮어쓰지 않습니다. 다만 LLMGoat·DVLA 등 일부 upstream base가 이동 태그이므로 같은 소스를 나중에 다시 빌드했을 때 byte-identical 결과까지 보장하지 않습니다. 실측 증거에는 commit 태그와 함께 pull된 image digest를 기록합니다.

로컬 진단 빌드는 태그를 반드시 명시합니다.

```bash
SETUP_COMMIT=$(git rev-parse HEAD)
cd docker
DOCKERHUB_NAMESPACE=your-namespace \
TAG="sha-$SETUP_COMMIT" \
  ./build-and-push.sh
```

`vuln-rag`와 `vuln-agent`만 같은 태그의 `base-gpu`를 `BASE_IMAGE`로 전달받습니다. LLMGoat와 DVLA는 각 upstream base를 사용합니다.

## EC2 운영

수동 `podman run`이나 Compose 대신 저장소 루트의 설치 스크립트를 사용합니다.

```bash
git fetch origin main
SETUP_COMMIT=$(git rev-parse origin/main)
sudo env IMAGE_NAMESPACE=gasbugs IMAGE_TAG="sha-$SETUP_COMMIT" \
  LAB_SETUP_REPO_RAW_URL="https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/$SETUP_COMMIT" \
  bash infrastructure/scripts/student/install-lab.sh

sudo -u ubuntu podman ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
sudo -u ubuntu podman logs --tail 100 lab-day3-vuln-rag
```

EC2는 이미지·모델 설치를 위해 인터넷 egress를 사용합니다. 기본 ingress는 `127.0.0.1/32`이고 브라우저/API 접근은 SSM 포트포워딩을 권장합니다.

## 보안 표시

`vuln-*` 이미지는 교육 목적으로 의도적으로 취약합니다.

```dockerfile
LABEL owasp.llm.lab.warning="INTENTIONALLY VULNERABLE — DO NOT DEPLOY OUTSIDE TRAINING"
```

허가된 개인 실습 계정 밖에 배포하지 마세요. 실제 검증 절차는 [`docs/LIVE-VALIDATION.md`](../docs/LIVE-VALIDATION.md)를 사용합니다.
