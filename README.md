# OWASP LLM Lab Setup Guide

수강생이 본인 AWS 계정에 OWASP Top 10 for LLM 실습 환경을 만들고, 컨테이너 애플리케이션을 배포하고, 매일 안전하게 시작/종료할 수 있도록 정리한 공개 가이드입니다.

> WARNING: 이 저장소의 일부 컨테이너는 교육 목적으로 의도적으로 취약하게 만든 실습 앱입니다. 허가된 개인 실습 계정과 강의 범위 안에서만 사용하세요.

## 무엇이 포함되어 있나요

| 경로 | 용도 |
|---|---|
| `docs/STUDENT-QUICKSTART.md` | 수강생이 따라 하는 Day 0 셋업 절차 |
| `docs/ARCHITECTURE.md` | AWS VM, Terraform, user-data, 컨테이너 배포 구조 |
| `docs/INSTRUCTOR-IMAGE-BUILD.md` | 강사가 컨테이너 이미지를 빌드하고 Docker Hub에 push하는 절차 |
| `docs/TROUBLESHOOTING.md` | quota, SSM, Terraform, Podman, Ollama 문제 해결 |
| `infrastructure/terraform/` | VPC, 보안 그룹, EC2 g6.xlarge, IAM, Budget 알람 |
| `infrastructure/terraform/user-data.sh.tpl` | 최초 부팅 시 Podman 설치, 이미지 pull, 실습 컨테이너 run |
| `infrastructure/scripts/student/` | 학생용 preflight, instance-id, start, stop, sync 헬퍼 |
| `infrastructure/packer/` | 선택 사항: 강사용 Golden AMI 빌드 |
| `docker/` | 실습 컨테이너 Dockerfile, compose, 취약 RAG/Agent 앱 코드 |

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
# terraform.tfvars에서 region, golden_ami_id, student_ids, alert_email 수정

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

1. Terraform이 학생별 EC2 `g6.xlarge` 1대를 만듭니다.
2. EC2 최초 부팅 시 `user-data.sh.tpl`이 실행됩니다.
3. user-data가 Podman을 설치하고 실습 컨테이너 이미지를 pull합니다.
4. `lab-ollama`, `lab-vuln-rag`, `lab-vuln-agent`, `lab-llmgoat`, `lab-dvla`, `lab-fake-registry` 컨테이너를 실행합니다.
5. systemd user unit을 등록하여 EC2 stop/start 후에도 컨테이너가 자동 재시작됩니다.

## 비용 안전 원칙

- `g6.xlarge`는 실행 중일 때 비용이 발생합니다.
- `stop` 상태에서는 EC2 시간당 요금이 멈추지만 EBS 비용은 남습니다.
- 매일 실습 종료 후 반드시 `stop-lab.sh`를 실행하세요.
- 강의 종료 후에는 보존할 작업물을 개인 GitHub repo에 push한 뒤 `terraform destroy`를 실행하세요.
- Budget은 비용을 막아 주는 장치가 아니라 경보입니다. 알람이 오면 즉시 stop 상태를 확인하세요.

## 보안 원칙

- `allowed_ingress_cidr` 기본값은 `127.0.0.1/32`입니다. 기본적으로 외부 직접 접속을 닫고 SSM 포트포워딩을 사용합니다.
- 브라우저 직접 접속이 필요한 경우에만 본인 공인 IP `/32`로 제한하세요.
- `0.0.0.0/0` 또는 `::/0` 공개는 Terraform validation에서 차단됩니다.
- Access Key, Secret, `terraform.tfvars`, `.tfstate` 파일은 절대 commit하지 마세요.

## 라이선스와 주의

이 저장소 자체는 MIT License로 배포됩니다. 단, `docker/llmgoat`와 `docker/dvla`는 각각 원본 오픈소스 프로젝트를 컨테이너화한 wrapper이며, 해당 원본 프로젝트의 라이선스와 고지 사항을 함께 따릅니다.

