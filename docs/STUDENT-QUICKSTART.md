# Student Quickstart

이 문서는 수강생이 본인 AWS 계정에 실습 VM과 컨테이너 앱을 배포하는 절차입니다.

## 0. 준비물

- AWS 계정과 결제 수단
- AWS CLI v2
- Session Manager Plugin
- Terraform 1.x
- Git
- 강사가 공지한 AWS 리전
- 비용 알람을 받을 이메일

## 1. AWS CLI 설정

```bash
aws configure --profile owasp-llm
aws sts get-caller-identity --profile owasp-llm
```

`aws sts get-caller-identity`가 본인 계정 ARN을 출력하면 통과입니다.

## 2. GPU quota 확인

기본값 `g6.xlarge`는 4 vCPU를 사용합니다. 아래 quota가 4 이상이어야 합니다.

```bash
aws service-quotas get-service-quota \
  --profile owasp-llm --region us-east-1 \
  --service-code ec2 --quota-code L-DB2E81BA \
  --query "Quota.{Name:QuotaName,Value:Value}"
```

0 또는 4 미만이면 AWS Console의 Service Quotas에서 `Running On-Demand G and VT instances` 증설을 신청하세요.

## 3. 로컬 preflight

저장소 루트에서 실행합니다.

```bash
AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 \
  bash infrastructure/scripts/student/preflight-local.sh
```

`Preflight PASS`가 나오면 다음 단계로 진행합니다.

## 4. Terraform 변수 작성

```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
```

`terraform.tfvars`에서 최소 아래 값을 수정합니다.

```hcl
aws_profile = "owasp-llm"
region      = "us-east-1"
course_id   = "owasp-llm-2026"

student_ids = ["yourname"]

course_dates = [
  "2026-09-07",
  "2026-09-08",
  "2026-09-09",
  "2026-09-10",
  "2026-09-11",
]

# AMI ID는 직접 입력하지 않습니다.
# Terraform이 기존 검증 계열의 최신 DLAMI를 자동 조회합니다.

allowed_ingress_cidr = "127.0.0.1/32"

# 기본값은 수동 설치입니다.
enable_user_data_bootstrap = false

daily_budget_usd  = 20
course_budget_usd = 120
alert_email       = "your@email.com"

# 기본 인스턴스 타입은 g6.xlarge입니다.
# instance_type = "g6.xlarge"
```

## 5. VM 생성

```bash
terraform init
terraform plan
terraform apply -auto-approve
```

성공하면 `ami_id`, `ami_name`, `instance_ids`, `public_ips`, `manual_install_commands`, `start_commands`, `stop_commands`, `ssm_session_commands`가 출력됩니다.

## 6. SSM 접속

기본값에서는 EC2만 생성되고 실습 앱은 아직 설치되지 않습니다. 먼저 SSM으로 인스턴스에 접속합니다.

저장소 루트에서 실행합니다.

```bash
export STUDENT=yourname
export INSTANCE_ID=$(AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT="$STUDENT" \
  bash infrastructure/scripts/student/instance-id.sh)

aws ssm start-session --profile owasp-llm --region us-east-1 \
  --target "$INSTANCE_ID"
```

## 7. 실습 앱 직접 설치

SSM 세션 안에서 아래 명령을 실행합니다. Terraform output의 `manual_install_commands`에 같은 명령이 표시됩니다.

```bash
curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/install-lab.sh | sudo bash
```

설치 중 수행되는 작업은 다음과 같습니다.

- Podman 설치
- NVIDIA CDI 설정
- Ollama 컨테이너 실행
- `llama3.1:8b-instruct-q4_K_M` 모델 pull 및 warm-up
- 취약 RAG 앱 실행: `lab-vuln-rag`, port `8000`
- 취약 Agent 앱 실행: `lab-vuln-agent`, port `8001`
- LLMGoat 실행: `lab-llmgoat`, port `5000`
- DVLA 실행: `lab-dvla`, port `8501`
- fake model registry 실행: `lab-fake-registry`, port `8002`
- EC2 start 후 자동 재시작을 위한 Podman Quadlet systemd user unit 등록
- Terraform 기본 설정으로 17:30 KST부터 다음날 08:30 KST까지 30분마다 Lambda 기반 EC2 자동 중지 등록

설치 로그는 EC2 안의 `/var/log/owasp-llm-lab-install.log`에서 확인할 수 있습니다.

자동 설치가 필요한 경우에는 `terraform.tfvars`에 아래 값을 넣은 뒤 새 인스턴스를 만들면 됩니다.

```hcl
enable_user_data_bootstrap = true
```

## 8. 컨테이너 상태 확인

SSM 세션 안에서 실행합니다.

```bash
sudo -u ubuntu podman ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
curl -s http://localhost:11434/api/tags | head
curl -s http://localhost:8000/healthz
curl -s http://localhost:8001/healthz
curl -s http://localhost:8002/api/v1/models | head
```

## 9. 설치를 다시 해야 할 때

설치가 중간에 실패했거나 깨끗하게 다시 올리고 싶으면 SSM 세션 안에서 클린업 후 설치를 다시 실행합니다.

```bash
curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/cleanup-lab.sh | sudo bash
curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/install-lab.sh | sudo bash
```

모델 캐시와 생성 파일까지 지우려면 `--purge`를 사용합니다. 이 경우 다음 설치에서 모델을 다시 받아 시간이 더 걸립니다.

```bash
curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/cleanup-lab.sh | sudo bash -s -- --purge
```

## 10. 매일 시작

```bash
AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT=yourname \
  bash infrastructure/scripts/student/start-lab.sh
```

## 11. 매일 종료

```bash
AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT=yourname \
  bash infrastructure/scripts/student/stop-lab.sh
```

이 명령을 실행하면 EC2 시간당 요금이 멈춥니다. EBS 비용은 남습니다.

## 12. 강의 종료 후 삭제

보존할 작업물을 먼저 개인 GitHub repo에 push하세요.

```bash
cd infrastructure/terraform
terraform destroy
```

## 13. 절대 하지 말 것

- `allowed_ingress_cidr = "0.0.0.0/0"`로 바꾸지 마세요.
- Access Key와 Secret을 GitHub에 올리지 마세요.
- `terraform.tfvars`, `.tfstate`, `.pem` 파일을 commit하지 마세요.
- 취약 컨테이너를 회사/고객사/공개 서비스 환경에 배포하지 마세요.
