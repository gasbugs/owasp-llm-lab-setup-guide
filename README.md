# OWASP LLM Lab Setup Guide

OWASP Top 10 for LLM 실습의 AWS 인프라, 컨테이너 런타임, 설치 스크립트와 강사용 실측 검증을 함께 관리하는 공개 설정 저장소입니다. EC2에 무엇을 설치하고 어떤 이미지·포트·health 계약을 검증하는지는 이 저장소를 단일 기준으로 삼습니다.

> WARNING: 이 저장소의 일부 컨테이너는 교육 목적으로 의도적으로 취약하게 만든 실습 앱입니다. 허가된 개인 실습 계정과 강의 범위 안에서만 사용하세요.

## 무엇이 포함되어 있나요

| 경로 | 용도 |
|---|---|
| `docs/STUDENT-QUICKSTART.md` | 수강생이 따라 하는 Day 0 셋업 절차 |
| `docs/ARCHITECTURE.md` | AWS VM, Terraform, user-data, 컨테이너 배포 구조 |
| `docs/INSTRUCTOR-IMAGE-BUILD.md` | 강사가 컨테이너 이미지를 빌드하고 Docker Hub에 push하는 절차 |
| `docs/LIVE-VALIDATION.md` | commit 태그와 resolved digest로 EC2 런타임을 설치하고 증거를 회수하는 강사용 절차 |
| `docs/TROUBLESHOOTING.md` | quota, SSM, Terraform, Podman, Ollama 문제 해결 |
| `infrastructure/terraform/` | VPC, 보안 그룹, EC2 GPU 인스턴스, IAM, Budget 알람 |
| `infrastructure/terraform/user-data.sh.tpl` | 선택적 자동 설치용 user-data 래퍼. 기본값에서는 비활성화 |
| `infrastructure/scripts/student/` | 수강생용 preflight, 수동 설치/클린업, instance-id, start, stop, sync 헬퍼 |
| `infrastructure/packer/` | 선택 사항: 강사용 Golden AMI 빌드 |
| `docker/` | 이미지 Dockerfile·build helper·취약 앱 소스. 실제 배포 unit은 `install-lab.sh`가 생성하는 Quadlet |
| `tests/unit/` | 파서·UI 계약·공개 저장소 PII/secret 회귀 검사 |
| `tests/e2e/` | 공개 강사용 런타임 실측 검증. 수강생 과제나 채점 기준이 아님 |

## 빠른 시작

수강생은 아래 문서부터 보면 됩니다.

[docs/STUDENT-QUICKSTART.md](docs/STUDENT-QUICKSTART.md)

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
6. `lab-ollama`, `lab-portal`, `lab-day1-vuln-rag`~`lab-day5-vuln-rag`, `lab-day3-vuln-agent`, `lab-llmgoat`, `lab-day3-dvla`, `lab-day2-fake-registry` 컨테이너를 실행합니다.
7. Podman Quadlet 기반 systemd user unit을 등록하여 EC2 stop/start 후에도 컨테이너가 자동 재시작됩니다.

## 강사용 런타임 검증

컨테이너 변경은 CI의 unit·Python compile·shell syntax·Terraform·Packer·Docker build-config·공개 저장소 위생 검사를 통과한 뒤에만 Docker Hub로 push됩니다. `sha-<40자리 Git commit>` 태그는 한 번 publish되면 workflow와 로컬 helper가 덮어쓰기를 거부하며, 모든 이미지 빌드가 끝난 경우에만 그 이미지 세트를 `latest`로 승격합니다.

실측 검증에서는 `latest` 대신 검증할 커밋 태그를 지정하고, 실제 pull된 각 이미지의 resolved digest를 함께 기록하세요. 일부 upstream base image와 설치 스크립트가 이동 태그를 사용하므로 Git commit만으로 bit-for-bit 재빌드를 보장하지 않으며, 최초 publish된 digest가 최종 실행 식별자입니다.

```bash
git fetch origin main
SETUP_COMMIT=$(git rev-parse origin/main)
sudo env IMAGE_NAMESPACE=gasbugs IMAGE_TAG="sha-$SETUP_COMMIT" \
  LAB_SETUP_REPO_RAW_URL="https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/$SETUP_COMMIT" \
  bash infrastructure/scripts/student/install-lab.sh

TRIALS=5 bash tests/e2e/run-full-cycle.sh
```

전체 절차와 결과 경로는 [docs/LIVE-VALIDATION.md](docs/LIVE-VALIDATION.md)에 고정합니다.

강사가 운영 편의상 자동 설치를 원하면 `terraform.tfvars`에 아래 값을 추가합니다.

```hcl
enable_user_data_bootstrap = true
```

자동 설치를 켜도 내부적으로는 수강생용 `infrastructure/scripts/student/install-lab.sh`와 같은 설치 절차를 실행합니다.

## 비용 안전 원칙

- `g6.xlarge`는 실행 중일 때 비용이 발생합니다.
- `stop` 상태에서는 EC2 시간당 요금이 멈추지만 EBS 비용은 남습니다.
- 매일 실습 종료 후 반드시 `stop-lab.sh`를 실행하세요. 자동 중지를 기다리는 것은 정상 종료 절차가 아닙니다.
- 기본 Terraform 설정은 수동 종료 누락에 대비한 보조 안전장치로 매일 17:30 KST에 Lambda를 호출해 실행 중인 실습 EC2를 자동 중지합니다. `auto_stop_schedule_mode`로 야간 반복 모드나 custom cron으로 바꿀 수 있습니다.
- 강의 종료 후에는 보존할 작업물을 개인 GitHub repo에 push한 뒤 `terraform destroy`를 실행하세요.
- Budget은 비용을 막아 주는 장치가 아니라 경보입니다. 알람이 오면 즉시 stop 상태를 확인하세요.

## 보안 원칙

- `allowed_ingress_cidr` 기본값은 `127.0.0.1/32`입니다. 기본적으로 외부 직접 접속을 닫고 SSM 포트포워딩을 사용합니다.
- 브라우저 직접 접속이 필요한 경우에만 본인 공인 IP `/32`로 제한하세요.
- `0.0.0.0/0` 또는 `::/0` 공개는 Terraform validation에서 차단됩니다.
- Access Key, Secret, `terraform.tfvars`, `.tfstate` 파일은 절대 commit하지 마세요.

## 라이선스와 주의

이 저장소 자체는 MIT License로 배포됩니다. 단, `docker/llmgoat`와 `docker/dvla`는 각각 SECFORCE/LLMGoat와 ReversecLabs/damn-vulnerable-llm-agent를 컨테이너화한 wrapper이며, 해당 원본 프로젝트의 라이선스와 고지 사항을 함께 따릅니다.
