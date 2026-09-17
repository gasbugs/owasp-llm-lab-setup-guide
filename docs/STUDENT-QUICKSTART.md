# Student Quickstart

이 문서는 수강생이 본인 AWS 계정에 실습 VM과 컨테이너 앱을 배포하는 절차입니다.

## 0. 준비물

- AWS 계정과 결제 수단
- AWS CLI v2
- Session Manager Plugin
- Terraform 1.x
- Git
- 강사가 공지한 AWS 리전

Ubuntu PC에서 위 도구를 한 번에 준비하려면 다음 선택적 스크립트를 실행할 수
있습니다. 이 스크립트의 Docker는 로컬 개발용이며, EC2 실습 앱은 7단계의
`install-lab.sh`가 Docker과 단일 Compose 파일로 구성합니다.

```bash
curl -fsSLO https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/setup-workstation-ubuntu.sh
bash setup-workstation-ubuntu.sh
cd ~/owasp-llm-lab-setup-guide
```

macOS와 Windows에서는 이 Ubuntu 전용 스크립트를 실행하지 말고 준비물에 적힌
도구를 각 운영체제의 공식 설치 방법으로 설치하세요.

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

# false는 SSM 접속 후 수동 설치, true는 EC2 최초 부팅 때 자동 설치입니다.
enable_user_data_bootstrap = false

# 기본값은 외부 접속을 열지 않습니다.
allowed_ingress_cidr = "127.0.0.1/32"

```

AMI ID는 직접 입력하지 않습니다. Terraform이 검증된 계열의 최신 DLAMI를 조회하고 `g6.xlarge`, 100GB를 기본값으로 적용합니다. `enable_user_data_bootstrap = false`는 수강생이 SSM으로 접속해 설치 과정을 직접 확인하는 정본이며, 강사용 자동 설치에서는 이 값을 `true`로 바꿉니다. EC2 공인 IP에 직접 접속하려면 `allowed_ingress_cidr`를 본인의 현재 공인 IPv4 `/32`로 바꿉니다. AMI·commit 고정이 필요한 강사용 환경만 [Terraform 고급 설정](TERRAFORM-ADVANCED-OPTIONS.md)을 참고합니다.

## 5. VM 생성

```bash
terraform init
terraform plan
terraform apply -auto-approve
```

성공하면 `ami_id`, `ami_name`, `availability_zones`, `autoscaling_group_name`, `instance_lookup_command`, `public_ip_lookup_command`, `start_command`, `stop_command`, `ssm_session_command`가 출력됩니다.

## 6. SSM 접속

기본값에서는 EC2만 생성되고 실습 앱은 아직 설치되지 않습니다. 먼저 SSM으로 인스턴스에 접속합니다.

저장소 루트에서 실행합니다.

```bash
export INSTANCE_ID=$(AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 \
  bash infrastructure/scripts/student/instance-id.sh)

aws ssm start-session --profile owasp-llm --region us-east-1 \
  --target "$INSTANCE_ID"
```

## 7. 실습 앱 직접 설치

SSM 세션 안에서 아래 명령을 실행합니다. Terraform output의 `manual_install_command`에 같은 명령이 표시됩니다.

```bash
curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/install-lab.sh | sudo bash
```

설치 중 수행되는 작업은 다음과 같습니다.

- Docker 설치
- NVIDIA CDI 설정
- Ollama 컨테이너 실행
- `qwen3:14b-q4_K_M` 생성 모델(9.3GB)과 `bge-m3:latest` embedding 모델 pull 및 warm-up. 로컬 Guard 모델은 설치하지 않습니다. 자체 앱은 `think:false`로 답변·구조화 JSON만 생성하며 서버 인가와 근거 검증은 별도로 유지합니다.
- LLM08 서버 vector 분석용 `~/work/llm08-analysis-venv` 준비(NumPy만 설치)
- URI reverse proxy 실행: `lab-reverse-proxy`, port `80`
- 실습 포털 backend 실행: `lab-portal`, 기존 port `8080`
- 역할별 취약 앱 실행: `lab-prompt-rag`, `lab-llm04-rag`, `lab-data-rag`, `lab-output-rag`, `lab-knowledge-rag`, `lab-resource-rag`, ports `8000`, `8004`, `8010`, `8011`, `8012`, `8013`
- 취약 Agent 앱 실행: `lab-vuln-agent`, port `8001`
- LLMGoat 실행: `lab-llmgoat`, port `5000`
- DVLA 실행: `lab-dvla`, 내부 port `8501` (`lab-reverse-proxy`가 `/dvla/`와 기존 host `8501`로 전달)
- Day 4 LLM03 fake model registry 실행: `lab-fake-registry`, port `8002`
- 단일 Docker Compose 파일로 모든 서비스 실행
- EC2 재부팅 후 자동 복구를 위한 `restart: always`와 `Docker daemon` 설정
- 자동 중지 Lambda·EventBridge는 설치하지 않음. 실습 직후 `stop-lab.sh`로 ASG를 0으로 낮춰 EC2와 root EBS 삭제

설치 로그는 EC2 안의 `/var/log/owasp-llm-lab-install.log`에서 확인할 수 있습니다.

### 본인 공인 IPv4에서 실습 서비스에 접속

Terraform은 포트별 Security Group 규칙을 만들지 않습니다. 기본 `127.0.0.1/32`는 외부 인바운드를 열지 않으므로 SSM 포트포워딩을 사용합니다. 직접 접속이 필요하면 `allowed_ingress_cidr`에 본인 공인 IPv4 `/32`를 입력합니다. 이 경우 그 주소의 모든 프로토콜과 포트를 ingress 규칙 하나로 허용하며, `public_ip_lookup_command`로 확인한 EC2 공인 IP를 브라우저 주소에 사용합니다. Portal은 `http://EC2_PUBLIC_IP/`이고 UI는 `/prompt-rag/`, `/llm04-rag/`, `/data-rag/`, `/output-rag/`, `/knowledge-rag/`, `/resource-rag/`, `/vuln-agent/`, `/llmgoat/`, `/dvla/`에서 엽니다. `0.0.0.0/0`으로 넓히지 않습니다.

Nginx는 URI를 내부 서비스로 연결할 뿐 인증·인가를 대신하지 않습니다. 기존 `curl http://localhost:<port>/...` 명령은 그대로 사용하고 브라우저 UI만 port 80 진입점을 사용합니다.

### LLM08 추가 셋업

LLM08은 일반 컨테이너 설치 외에 embedding 모델/API, NumPy 분석 venv와 학습자 미니 앱 scaffold를 함께 확인해야 합니다. 강사·콘텐츠 배포자가 [LLM08 embedding lab setup](LLM08-SETUP.md)의 **publish gate를 먼저 통과해 공지한 40자리 setup commit**을 받은 뒤, 새 EC2 또는 기존 EC2 경로를 선택해 진행하세요. Module 08·09의 WSL 제어면은 로컬 Docker Engine과 Compose v2를 사용하므로 3절 preflight에서 두 명령도 함께 검사합니다.

이 문서나 코드가 아직 로컬 워킹트리에만 있고 공개 `origin/main` commit 또는 그 commit의 GHCR 이미지가 없다면 수강생 환경은 준비된 것이 아닙니다. `main`/`latest`를 무조건 재실행하지 말고, 강사가 공지한 40자리 setup commit과 `sha-<commit>` 이미지가 모두 공개된 뒤 설치합니다.

LLM08 설치가 끝나면 최소 다음 계약을 확인합니다.

- `lab-ollama`에 `bge-m3:latest`가 존재
- `http://localhost:8012/healthz`가 `default_scenario=day4`
- 인증된 `POST /api/embed`가 양의 `dimensions`와 동일 길이 vector를 반환
- `~/work/llm08-analysis-venv`에서 NumPy import 가능
- commit에 고정된 `examples/llm08/mini_vector_search_app.py`를 별도 학습자 작업본으로 복사 가능
- 앱/API 증거를 보존하고 미니 앱을 정리한 다음, 모든 작업의 마지막에 EC2를 중지해 `stopped` 확인

자동 설치가 필요한 경우에는 `terraform.tfvars`에 아래 값을 넣은 뒤 새 인스턴스를 만들면 됩니다.

```hcl
enable_user_data_bootstrap = true
```

강사가 commit 고정값을 공지한 경우에는 [Terraform 고급 설정](TERRAFORM-ADVANCED-OPTIONS.md)의 `lab_setup_repo_raw_url`, `lab_image_namespace`, `lab_image_tag`를 공지값대로 추가합니다. 이 값들은 최초 `terraform apply` 전에 설정해야 합니다. 기존 인스턴스에서 값을 바꿔도 `user_data_replace_on_change = false` 설정 때문에 자동 설치가 다시 실행되지는 않습니다.

## 8. 컨테이너 상태 확인

SSM 세션 안에서 실행합니다.

모든 컨테이너는 `Network=host`를 사용하지 않고 Compose의 격리된 network에서 실행됩니다. 기존 직접 포트와 Nginx 80·8501 호환 포트는 `docker ps`의 `PORTS` 열에서 확인합니다. RAG·Agent·DVLA는 Compose service DNS인 `ollama:11434`로 Ollama를 호출합니다.

```bash
sudo -u ubuntu sh -lc 'cd ~/.config/owasp-llm-lab && docker compose ps'
sudo -u ubuntu docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
curl -s http://localhost/ | head
curl -s http://localhost/prompt-rag/healthz
curl -s http://localhost/llm04-rag/healthz
curl -s http://localhost/llmgoat/api/model_status
curl -s http://localhost/dvla/_stcore/health
curl -s http://localhost:8080/ | head
curl -s http://localhost:11434/api/tags | head
curl -s http://localhost:8000/healthz
curl -s http://localhost:8004/healthz
curl -s http://localhost:8010/healthz
curl -s http://localhost:8011/healthz
curl -s http://localhost:8012/healthz
curl -s http://localhost:8013/healthz
curl -s http://localhost:8001/healthz
curl -s http://localhost:5000/api/model_status
curl -s http://localhost:8002/api/v1/models | head
```

배포 정의 전체는 `~/.config/owasp-llm-lab/compose.yaml` 한 파일에서 확인할 수 있습니다. 개별 로그와 재시작도 컨테이너 이름으로 수행합니다.

```bash
sudo -u ubuntu docker logs --tail 100 lab-llmgoat
sudo -u ubuntu docker restart lab-llmgoat
```

## 9. 상태를 바꾼 실습만 최소 복원

일반 채팅처럼 읽기만 한 실습은 복원하지 않습니다. Python 메모리나 컨테이너
안의 source를 바꾼 실습만 Compose 서비스 이름을 지정해 다시 만들고, 이어서
raw `/healthz`를 확인합니다. 먼저 `cd ~/.config/owasp-llm-lab`로 이동한 뒤 아래에서
자신이 방금 수행한 실습만 실행합니다. `--no-deps`는 다른 서비스를 그대로 두고,
`--force-recreate`는 선택한 컨테이너의 writable layer를 새것으로 바꿉니다.

| 실습 | 재시작 명령 | 원본 확인 명령 |
|---|---|---|
| LLM01 시큐어 코딩 | `docker compose up -d --no-deps --force-recreate prompt-rag` | `curl -sS http://localhost:8000/healthz` |
| LLM04 RAG | `docker compose up -d --no-deps --force-recreate llm04-rag` | `curl -sS http://localhost:8004/healthz` |
| LLM02 시큐어 코딩·LLM08 RAG corpus | `docker compose up -d --no-deps --force-recreate data-rag` | `curl -sS http://localhost:8010/healthz` |
| LLM05 | `docker compose up -d --no-deps --force-recreate output-rag` | `curl -sS http://localhost:8011/healthz` |
| LLM06 삭제 실습 | `docker compose up -d --no-deps --force-recreate vuln-agent` | `curl -sS http://localhost:8001/healthz` |
| LLM08·LLM09 시큐어 코딩 | `docker compose up -d --no-deps --force-recreate knowledge-rag` | `curl -sS http://localhost:8012/healthz` |
| LLMGoat 상태 변경 실습 | `docker compose restart llmgoat` | `curl -sS http://localhost:5000/api/model_status` |
| LLM10 시큐어 코딩·과부하 | 아래 순서대로 `resource-rag`와 `ollama` 처리 | `curl -sS http://localhost:8013/healthz` |

LLM10은 timeout 뒤 Day 5 앱과 공유 Ollama queue에 작업이 남을 수 있으므로
두 서비스를 눈에 보이는 순서로 직접 처리합니다.

```bash
cd ~/.config/owasp-llm-lab
docker compose up -d --no-deps --force-recreate resource-rag
docker compose restart ollama
curl -fsS http://localhost:11434/api/tags
docker compose up -d --no-deps --force-recreate resource-rag
docker compose ps resource-rag ollama
```

```bash
curl -sS http://localhost:8013/healthz
```

이 복원 명령들은 `~/work`의 evidence와 Capstone, Ollama 모델, LLMGoat
모델/cache를 건드리지 않습니다. 실습별 저장 위치와 복원 범위는 [Lab state
and reset policy](LAB-RESET-POLICY.md)에 정리되어 있습니다.

수강생이 실행한 미니 앱을 종료하는 일과 EC2를 중지하는
일은 상태 복원과 별개입니다.

## 10. 설치 자체를 다시 해야 할 때

설치가 중간에 실패했거나 Compose 정의 자체가 손상된 경우에만 SSM 세션 안에서
클린업 후 설치를 다시 실행합니다. 일반 실습 상태 복원에는 이 절차를 사용하지
않습니다.

```bash
curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/cleanup-lab.sh | sudo bash
curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/install-lab.sh | sudo bash
```

모델 캐시와 생성 파일까지 지우려면 `--purge`를 사용합니다. 이 경우 다음 설치에서 모델을 다시 받아 시간이 더 걸립니다.

```bash
curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/cleanup-lab.sh | sudo bash -s -- --purge
```

## 11. 매일 시작

```bash
AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 \
  bash infrastructure/scripts/student/start-lab.sh
```

## 12. 매일 종료

```bash
AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 \
  bash infrastructure/scripts/student/stop-lab.sh
```

이 명령은 ASG를 0으로 낮춰 EC2와 root EBS를 삭제하므로 두 자원의 비용이 멈춥니다.

## 13. 강의 종료 후 삭제

보존할 작업물을 먼저 개인 GitHub repo에 push하세요.

```bash
cd infrastructure/terraform
terraform destroy
```

## 14. 절대 하지 말 것

- `allowed_ingress_cidr = "0.0.0.0/0"`로 바꾸지 마세요.
- Access Key와 Secret을 GitHub에 올리지 마세요.
- `terraform.tfvars`, `.tfstate`, `.pem` 파일을 commit하지 마세요.
- 취약 컨테이너를 회사/고객사/공개 서비스 환경에 배포하지 마세요.
