# Student Quickstart

이 문서는 수강생이 본인 AWS 계정에 실습 VM과 컨테이너 앱을 배포하는 절차입니다.

## 0. 준비물

- AWS 계정과 결제 수단
- AWS CLI v2
- Session Manager Plugin
- Terraform 1.x
- Git
- 강사가 공지한 AWS 리전과 AMI ID
- 비용 알람을 받을 이메일

## 1. AWS CLI 설정

```bash
aws configure --profile owasp-llm
aws sts get-caller-identity --profile owasp-llm
```

`aws sts get-caller-identity`가 본인 계정 ARN을 출력하면 통과입니다.

## 2. GPU quota 확인

`g6.xlarge`는 4 vCPU를 사용합니다. 아래 quota가 4 이상이어야 합니다.

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

golden_ami_id = "ami-xxxxxxxxxxxxxxxxx"

allowed_ingress_cidr = "127.0.0.1/32"

daily_budget_usd  = 20
course_budget_usd = 120
alert_email       = "your@email.com"
```

## 5. VM 생성

```bash
terraform init
terraform plan
terraform apply -auto-approve
```

성공하면 `instance_ids`, `public_ips`, `start_commands`, `stop_commands`, `ssm_session_commands`가 출력됩니다.

## 6. 앱 배포는 언제 되나요?

EC2 최초 부팅 시 Terraform의 `user_data`가 자동 실행됩니다.

자동으로 수행되는 작업은 다음과 같습니다.

- Podman 설치
- NVIDIA CDI 설정
- Ollama 컨테이너 실행
- `llama3.1:8b-instruct-q4_K_M` 모델 pull 및 warm-up
- 취약 RAG 앱 실행: `lab-vuln-rag`, port `8000`
- 취약 Agent 앱 실행: `lab-vuln-agent`, port `8001`
- LLMGoat 실행: `lab-llmgoat`, port `5000`
- DVLA 실행: `lab-dvla`, port `8501`
- fake model registry 실행: `lab-fake-registry`, port `8002`
- EC2 start 후 자동 재시작을 위한 systemd user unit 등록
- 4시간 후 자동 stop 안전망 등록

## 7. SSM 접속

저장소 루트에서 실행합니다.

```bash
export STUDENT=yourname
export INSTANCE_ID=$(AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT="$STUDENT" \
  bash infrastructure/scripts/student/instance-id.sh)

aws ssm start-session --profile owasp-llm --region us-east-1 \
  --target "$INSTANCE_ID"
```

## 8. 컨테이너 상태 확인

SSM 세션 안에서 실행합니다.

```bash
sudo -u ubuntu podman ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
curl -s http://localhost:11434/api/tags | head
curl -s http://localhost:8000/healthz
curl -s http://localhost:8001/healthz
```

## 9. 매일 시작

```bash
AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT=yourname \
  bash infrastructure/scripts/student/start-lab.sh
```

## 10. 매일 종료

```bash
AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT=yourname \
  bash infrastructure/scripts/student/stop-lab.sh
```

이 명령을 실행하면 EC2 시간당 요금이 멈춥니다. EBS 비용은 남습니다.

## 11. 강의 종료 후 삭제

보존할 작업물을 먼저 개인 GitHub repo에 push하세요.

```bash
cd infrastructure/terraform
terraform destroy
```

## 12. 절대 하지 말 것

- `allowed_ingress_cidr = "0.0.0.0/0"`로 바꾸지 마세요.
- Access Key와 Secret을 GitHub에 올리지 마세요.
- `terraform.tfvars`, `.tfstate`, `.pem` 파일을 commit하지 마세요.
- 취약 컨테이너를 회사/고객사/공개 서비스 환경에 배포하지 마세요.

