# Infrastructure — 수강생 1인 1계정 EC2 실습 환경

본 디렉터리는 OWASP Top 10 for LLM 강의 실습 환경을 AWS에 만드는 Terraform과 운영 스크립트를 담고 있다. 현재 운영 모델은 **수강생별 ASG가 여러 AZ 중 가용 용량이 있는 곳에 EC2 `g6.xlarge` 1대를 만드는 방식**이다.

## 현재 운영 모델

- Terraform은 `g6.xlarge`를 제공하는 모든 AZ에 subnet을 만들고 ASG가 가용 용량을 찾아 배치하게 한다.
- 수강생은 `terraform apply`로 본인 ASG, Launch Template, IAM instance profile, 보안 그룹, 비용 알람을 만든다.
- 매일 아침 `start-lab.sh`로 ASG desired capacity를 1로 올려 새 인스턴스를 만든다.
- 매일 종료 시 `stop-lab.sh`로 desired capacity를 0으로 낮춰 인스턴스와 root EBS를 삭제한다.
- 기본 Terraform 설정은 매일 18:00 KST에 Lambda를 호출해 ASG를 0으로 축소한다.
- 마지막 날에는 `terraform destroy -auto-approve`로 EC2, EBS, VPC, 비용 알람을 삭제한다.
- 기본 웹 접속은 SSM 포트포워딩이다. public IP 직접 접속은 `allowed_ingress_cidr`를 본인 IP `/32`로 제한한 경우에만 사용한다.

## 구성 요소

| 경로 | 용도 |
|---|---|
| `terraform/` | 다중 AZ VPC, ASG, Launch Template, 보안 그룹, IAM instance profile, Budget 알람 |
| `scripts/student/` | 수강생용 preflight, 수동 설치, instance-id, start/stop 및 작업물 보존 안내 헬퍼 |

`scripts/student/upload-capstone.sh`는 런타임이나 e2e의 의존성이 아니라 선택적 SSM 전송 helper입니다. 별도 수강생 패키지 루트에서 실행하며 `TF_DIR`은 이 설정 저장소의 `infrastructure/terraform`을 가리켜야 합니다.

## 수강생 기본 절차

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

재현 가능한 실측 검증에서는 `lab_setup_repo_raw_url`과 `lab_image_tag`를 같은 40자리 main commit으로 고정한다. `user_data_replace_on_change = false`이므로 이 값은 최초 apply 전에 확정해야 하며, 기존 인스턴스의 변수만 변경해도 bootstrap은 재실행되지 않는다.

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

- `g6.xlarge`는 실행 중일 때 비용이 발생한다.
- ASG를 0으로 줄이면 EC2와 root EBS가 삭제되어 해당 리소스 비용이 멈춘다.
- `terraform.tfvars.example`의 Budget 금액은 예시다. 실제 일일/전체 예산은 강사가 공지한 최신 리전, 단가, 환율, VAT, 실습 시간 기준으로 조정한다.
- Budget은 경보다. 알람이 오면 즉시 `stop-lab.sh` 또는 강사 호출로 확인한다.

## 작업물 보존

ASG를 0으로 줄이면 root EBS도 삭제된다. 영구 보존할 페이로드와 메모는 `stop-lab.sh` 실행 전에 개인 저장소나 승인된 저장 위치로 옮긴다.
