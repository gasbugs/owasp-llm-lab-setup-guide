# OWASP LLM Lab Setup Guide

OWASP Top 10 for LLM 실습의 AWS 인프라, 컨테이너 런타임, 설치 스크립트와 강사용 실측 검증을 함께 관리하는 공개 설정 저장소입니다. EC2에 무엇을 설치하고 어떤 이미지·포트·health 계약을 검증하는지는 이 저장소를 단일 기준으로 삼습니다.

> WARNING: 이 저장소의 일부 컨테이너는 교육 목적으로 의도적으로 취약하게 만든 실습 앱입니다. 허가된 개인 실습 계정과 강의 범위 안에서만 사용하세요.

## 무엇이 포함되어 있나요

| 경로 | 용도 |
|---|---|
| `docs/STUDENT-QUICKSTART.md` | 수강생이 따라 하는 Day 0 셋업 절차 |
| `docs/LAB-RESET-POLICY.md` | Day 1~5 상태 저장 위치와 allowlist 기반 최소 복원 명령 |
| `docs/LLM08-SETUP.md` | LLM08 embedding runtime·분석 venv·학습자 미니 앱의 신규/기존 EC2 설치와 종료 절차 |
| `docs/MODULE08-EXERCISE-6.5.md` | 08챕터 6.5를 AWS·완성 이미지 없이 소스에서 직접 빌드하는 반복 실습 |
| `docs/DAY6-GUARDRAILS-SETUP.md` | Microsoft Presidio·NeMo Guardrails rootless Podman 이미지 빌드와 실측 검증 |
| `bedrock-api-lab/` | 기존 GPU 환경과 독립된 Nova Lite·Titan Embeddings·Knowledge Base API 실습 |
| `docs/ARCHITECTURE.md` | AWS VM, Terraform, user-data, 컨테이너 배포 구조 |
| `docs/INSTRUCTOR-IMAGE-BUILD.md` | 강사가 컨테이너 이미지를 빌드하고 공개 GHCR에 push하는 절차 |
| `docs/LIVE-VALIDATION.md` | commit 태그와 resolved digest로 EC2 런타임을 설치하고 증거를 회수하는 강사용 절차 |
| `docs/TROUBLESHOOTING.md` | quota, SSM, Terraform, Podman, Ollama 문제 해결 |
| `infrastructure/terraform/` | VPC, 보안 그룹, EC2 GPU 인스턴스, IAM, Budget 알람 |
| `infrastructure/terraform/user-data.sh.tpl` | 선택적 자동 설치용 user-data 래퍼. 기본값에서는 비활성화 |
| `infrastructure/scripts/student/` | 수강생용 preflight, 수동 설치/클린업, instance-id, start, stop, sync 헬퍼 |
| `infrastructure/packer/` | 선택 사항: 강사용 Golden AMI 빌드 |
| `infrastructure/compose/compose.yaml` | 포트·이미지·환경변수·볼륨·GPU·의존관계를 한눈에 보는 단일 서비스 배포 정의 |
| `docker/` | 이미지 Dockerfile·build helper·취약 앱 소스 |
| `tests/unit/` | 파서·UI 계약·공개 저장소 PII/secret 회귀 검사 |
| `tests/e2e/` | 공개 강사용 런타임 실측 검증. 수강생 과제나 채점 기준이 아님 |

## 빠른 시작

수강생은 아래 문서부터 보면 됩니다.

[docs/STUDENT-QUICKSTART.md](docs/STUDENT-QUICKSTART.md)

Ubuntu 로컬 PC의 선택적 도구 설치는
[`infrastructure/scripts/student/setup-workstation-ubuntu.sh`](infrastructure/scripts/student/setup-workstation-ubuntu.sh)를
사용합니다. 이 스크립트는 로컬 워크스테이션만 준비하며 EC2의 Podman 실습
런타임 설치를 대신하지 않습니다.

Day 2 LLM08에서는 일반 셋업 뒤 [docs/LLM08-SETUP.md](docs/LLM08-SETUP.md)의 `bge-m3:latest`/Day 4 API 검증, 미니 앱 실행·SSM forwarding·증거 보존을 추가로 수행합니다. 강사·콘텐츠 배포자가 먼저 publish gate를 통과해 40자리 setup commit을 공지하며, 수강생은 로컬 PC에 Podman을 추가 설치하지 않습니다. LLM08 변경이 로컬 워킹트리에만 있거나 같은 commit의 이미지가 아직 공개 GHCR에 없으면 gate에서 중단하며, 현재 원격 `main`에 이미 배포됐다고 가정하지 않습니다.

Day 6 가드레일 실습은 [docs/DAY6-GUARDRAILS-SETUP.md](docs/DAY6-GUARDRAILS-SETUP.md)를 따릅니다. 두 프레임워크는 호스트 Python이 아니라 독립된 rootless Podman 이미지에 설치되며, 기존 one-shot CLI와 loopback HTTP 통합 서버를 함께 제공합니다.

가장 짧은 흐름은 다음과 같습니다.

```bash
git clone https://github.com/gasbugs/owasp-llm-lab-setup-guide.git
cd owasp-llm-lab-setup-guide

AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 \
  bash infrastructure/scripts/student/preflight-local.sh

cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
# terraform.tfvars에서 region, student_ids, alert_email 수정

terraform init
terraform plan
terraform apply -auto-approve
```

매일 시작과 종료는 저장소 루트에서 실행합니다.

```bash
AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT=yourname \
  bash infrastructure/scripts/student/start-lab.sh

AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT=yourname \
  bash infrastructure/scripts/student/stop-lab.sh
```

## 기본 배포 방식

1. Terraform이 기존 검증 계열인 `Deep Learning OSS Nvidia Driver AMI GPU PyTorch 2.11 (Ubuntu 24.04)`의 최신 AMI를 조회합니다.
2. Terraform이 수강생별 EC2 `g6.xlarge` 1대를 만듭니다.
3. 기본값에서는 user-data 자동 설치가 실행되지 않습니다.
4. 수강생이 SSM으로 EC2에 접속해 `install-lab.sh`를 직접 실행합니다.
5. 설치 스크립트가 Podman을 설치하고 실습 컨테이너 이미지를 pull합니다.
6. `lab-ollama`, `lab-portal`, `lab-prompt-rag`, `lab-data-rag`, `lab-output-rag`, `lab-knowledge-rag`, `lab-resource-rag`, `lab-vuln-agent`, `lab-llmgoat`, `lab-dvla`, `lab-fake-registry` 컨테이너를 실행합니다.
7. 단일 Podman Compose 정의로 서비스를 실행하고 `restart: always` 정책과 `podman-restart.service`로 EC2 재부팅 후 자동 복구합니다.

AMI ID나 SHA를 직접 입력하는 변수는 두지 않습니다. 이름·소유자 조건에 맞는 최신 AMI 조회 결과는 새 EC2를 생성할 때 적용되며, 이미 존재하는 수강생 EC2는 EBS 작업물 보호를 위해 현재 AMI를 유지하고 자동 교체하지 않습니다.

## 강사용 런타임 검증

컨테이너 변경은 CI의 unit·Python compile·shell syntax·Terraform·Packer·Docker build-config·공개 저장소 위생 검사를 통과한 뒤에만 공개 GitHub Container Registry(GHCR)로 push됩니다. Workflow는 외부 registry secret 대신 내장 `GITHUB_TOKEN`의 `packages: write` 권한을 사용합니다. `sha-<40자리 Git commit>` 태그는 한 번 publish되면 workflow와 로컬 helper가 덮어쓰기를 거부하며, 모든 이미지 빌드가 끝난 경우에만 그 이미지 세트를 `latest`로 승격합니다.

실측 검증에서는 `latest` 대신 검증할 커밋 태그를 지정하고, 실제 pull된 각 이미지의 resolved digest를 함께 기록하세요. 일부 upstream base image와 설치 스크립트가 이동 태그를 사용하므로 Git commit만으로 bit-for-bit 재빌드를 보장하지 않으며, 최초 publish된 digest가 최종 실행 식별자입니다.

```bash
git fetch origin main
SETUP_COMMIT=$(git rev-parse origin/main)
sudo env IMAGE_NAMESPACE=gasbugs IMAGE_TAG="sha-$SETUP_COMMIT" \
  LAB_SETUP_REPO_RAW_URL="https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/$SETUP_COMMIT" \
  bash infrastructure/scripts/student/install-lab.sh

TRIALS=5 bash tests/e2e/run-full-cycle.sh
```

full-cycle은 RAG·Agent 항목뿐 아니라 LLMGoat A01/A02/A04/A06/A08을
loopback API로 실제 호출합니다. 각 응답은 `llmgoat/raw/requests.jsonl`에
보존하고, A04 review poison/reset과 A08 vector import/reset은 결정적 계약으로
반드시 통과시킵니다. 모델별 `solved` 여부는 배포 판정이 아니라 실측
관찰값입니다. 로컬 Playwright 단계는 SSM `5000→15000` 포워드를 통해 A01
화면의 응답 렌더링과 solved 표시 일치 여부도 확인합니다.

전체 절차와 결과 경로는 [docs/LIVE-VALIDATION.md](docs/LIVE-VALIDATION.md)에 고정합니다.

강사가 운영 편의상 자동 설치를 원하면 `terraform.tfvars`에 아래 값을 추가합니다.

```hcl
enable_user_data_bootstrap = true
```

자동 설치를 켜도 내부적으로는 수강생용 `infrastructure/scripts/student/install-lab.sh`와 같은 설치 절차를 실행합니다.
강사용 실측에서는 `lab_setup_repo_raw_url`과 `lab_image_tag`를 같은 40자리 main commit으로 고정해야 합니다. 예시는 `terraform.tfvars.example`과 [docs/LIVE-VALIDATION.md](docs/LIVE-VALIDATION.md)에 있습니다.

`user_data_replace_on_change = false`이므로 이 pin은 최초 `terraform apply` 전에 설정하세요. 기존 인스턴스에서 URL이나 이미지 태그만 바꿔도 user-data가 다시 실행되거나 인스턴스가 자동 교체되지는 않습니다.

## 비용 안전 원칙

- `g6.xlarge`는 실행 중일 때 비용이 발생합니다.
- `stop-lab.sh`는 ASG를 0으로 줄여 EC2와 root EBS를 삭제합니다.
- 매일 실습 종료 후 반드시 `stop-lab.sh`를 실행하세요. 자동 중지를 기다리는 것은 정상 종료 절차가 아닙니다.
- 기본 Terraform 설정은 수동 종료 누락에 대비해 매일 18:00 KST에 Lambda를 호출하고 수강생 ASG를 0으로 축소합니다. `auto_stop_schedule_mode`로 기존 17:30 모드, 야간 반복 모드 또는 custom cron으로 바꿀 수 있습니다.
- 강의 종료 후에는 보존할 작업물을 개인 GitHub repo에 push한 뒤 `terraform destroy`를 실행하세요.
- Budget은 비용을 막아 주는 장치가 아니라 경보입니다. 알람이 오면 즉시 stop 상태를 확인하세요.

실습 포트를 인터넷에 공개하지 않고 로컬에서 모두 사용하려면 수강생 노트북에서 다음 명령을 실행합니다. 자세한 포트 목록과 종료 방법은 `docs/STUDENT-QUICKSTART.md`를 참고합니다.

```bash
AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 \
  bash infrastructure/scripts/student/forward-lab-ports.sh i-0123456789abcdef0
```

## 보안 원칙

- `allowed_ingress_cidr` 기본값은 `127.0.0.1/32`입니다. 기본적으로 외부 직접 접속을 닫고 SSM 포트포워딩을 사용합니다.
- 브라우저 직접 접속이 필요한 경우에만 본인 공인 IP `/32`로 제한하세요.
- `0.0.0.0/0` 또는 `::/0` 공개는 Terraform validation에서 차단됩니다.
- Access Key, Secret, `terraform.tfvars`, `.tfstate` 파일은 절대 commit하지 마세요.

## 라이선스와 주의

이 저장소 자체는 MIT License로 배포됩니다. 단, `docker/llmgoat`와 `docker/dvla`는 각각 SECFORCE/LLMGoat와 ReversecLabs/damn-vulnerable-llm-agent를 컨테이너화한 wrapper이며, 해당 원본 프로젝트의 라이선스와 고지 사항을 함께 따릅니다.
