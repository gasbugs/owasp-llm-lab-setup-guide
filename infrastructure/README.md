# Infrastructure — 학생 1인 1계정 EC2 실습 환경

본 디렉터리는 OWASP Top 10 for LLM 강의 실습 환경을 AWS에 만드는 Terraform과 운영 스크립트를 담고 있다. 현재 운영 모델은 **학생 본인 AWS 계정에 EC2 GPU 인스턴스 1대를 만들고, 학생이 직접 start/stop하는 방식**이다. 기본값은 비용 절감형 `g4dn.xlarge`이며, 더 안정적인 운영이 필요하면 `g6.xlarge`를 선택한다.

## 현재 운영 모델

- 매일 새 환경을 자동 재배포하지 않는다. 같은 EC2와 EBS를 `stop/start`로 이어서 사용한다.
- 학생은 `terraform apply`로 본인 EC2, IAM instance profile, 보안 그룹, 비용 알람을 만든다.
- 매일 아침 `infrastructure/scripts/student/start-lab.sh`로 인스턴스를 시작한다.
- 매일 종료 시 `infrastructure/scripts/student/stop-lab.sh`로 EC2 시간당 요금을 멈춘다.
- 마지막 날에는 `terraform destroy -auto-approve`로 EC2, EBS, VPC, 비용 알람을 삭제한다.
- 기본 웹 접속은 SSM 포트포워딩이다. public IP 직접 접속은 `allowed_ingress_cidr`를 본인 IP `/32`로 제한한 경우에만 사용한다.

## 구성 요소

| 경로 | 용도 |
|---|---|
| `terraform/` | VPC, 보안 그룹, EC2, IAM instance profile, Budget 알람 |
| `scripts/student/` | 학생용 preflight, 수동 설치, instance-id, start/stop 및 작업물 보존 안내 헬퍼 |

## 학생 기본 절차

```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
# terraform.tfvars에서 student_ids, region, alert_email을 강사 공지 기준으로 수정
# AMI는 기존 검증 계열의 최신 DLAMI를 data source로 자동 조회
# 기본값은 user-data 자동 설치 비활성화. SSM 접속 후 install-lab.sh를 직접 실행
# allowed_ingress_cidr는 기본 127.0.0.1/32 유지. 직접 접속이 필요할 때만 본인 IP/32로 변경
terraform init
terraform plan
terraform apply -auto-approve
```

Terraform 적용 후 EC2 안에서 설치를 직접 수행한다.

```bash
curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/install-lab.sh | sudo bash
```

강사 운영상 자동 설치가 필요할 때만 `terraform.tfvars`에 아래 값을 추가한다.

```hcl
enable_user_data_bootstrap = true
```

이후 매일 시작/종료는 저장소 루트에서 실행한다.

```bash
AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 \
  bash infrastructure/scripts/student/preflight-local.sh

AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT=yourname \
  bash infrastructure/scripts/student/start-lab.sh

export INSTANCE_ID=$(AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT=yourname \
  bash infrastructure/scripts/student/instance-id.sh)

AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT=yourname \
  bash infrastructure/scripts/student/stop-lab.sh
```

## 비용 가드레일

- GPU 인스턴스는 실행 중일 때 비용이 발생한다. 비용 절감 기본값은 `g4dn.xlarge`, 안정 운영 옵션은 `g6.xlarge`다.
- `stop` 상태에서는 EC2 시간당 요금은 멈추지만 EBS 보존 비용은 남는다.
- `terraform.tfvars.example`의 Budget 금액은 예시다. 실제 일일/전체 예산은 강사가 공지한 최신 리전, 단가, 환율, VAT, 실습 시간 기준으로 조정한다.
- Budget은 경보다. 알람이 오면 즉시 `stop-lab.sh` 또는 강사 호출로 확인한다.

## 작업물 보존

인스턴스를 `stop`하면 EBS 디스크는 유지되므로 다음날 이어서 실습할 수 있다. 다만 마지막 날 `terraform destroy`를 실행하면 디스크도 삭제된다. 영구 보존할 페이로드, 메모, Capstone 코드는 destroy 전에 개인 GitHub 작업 repo에 push한다.
