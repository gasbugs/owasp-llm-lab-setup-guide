# Infrastructure — 수강생 1인 1계정 EC2 실습 환경

본 디렉터리는 OWASP Top 10 for LLM 강의 실습 환경을 AWS에 만드는 Terraform과 운영 스크립트를 담고 있다. 현재 운영 모델은 **수강생 계정에 On-Demand EC2 `g6.xlarge` 1대를 만들고 같은 인스턴스를 중지·재시작하는 방식**이다.

## 현재 운영 모델

- Terraform은 `g6.xlarge`를 제공하는 AZ에 subnet을 만들고 그중 한 곳에 EC2를 배치한다. 기본은 첫 지원 AZ이며 신규 생성 시 용량이 부족하면 `availability_zone`을 지정한다.
- 수강생은 `terraform apply`로 본인 계정에 EC2, IAM instance profile, 보안 그룹을 만든다.
- 다시 실습할 때 `start-lab.sh`로 기존 인스턴스를 시작한다.
- 실습 종료 시 `stop-lab.sh`로 EC2를 중지한다. root EBS의 모델·작업물은 보존된다.
- 자동 중지 Lambda·EventBridge는 만들지 않는다. 실습 직후 직접 중지하고 `stopped`를 확인한다.
- 마지막 날에는 `terraform destroy -auto-approve`로 EC2, EBS, VPC를 삭제한다.
- 보안 그룹은 포트별 규칙 대신 `allowed_ingress_cidr`의 본인 공인 IPv4 `/32`에서 오는 전체 인바운드 트래픽을 허용한다. 학습자 웹/API는 EC2 public IP로 직접 접속하고 SSM은 셸 접속에 사용한다.
- Bootstrap 또는 수동 설치가 끝나면 브라우저 UI는 Nginx의 TCP/80 하나에서 URI별로 연결된다.

## 구성 요소

| 경로 | 용도 |
|---|---|
| `terraform/` | VPC, 단일 On-Demand EC2, 보안 그룹, IAM instance profile |
| `compose/compose.yaml` | 12개 실습 컨테이너의 단일 Docker Compose 배포 정의 |
| `reverse-proxy/default.conf` | port 80의 UI URI를 기존 Compose 서비스로 전달하는 Nginx 설정 |
| `scripts/student/` | 수강생용 preflight, 수동 설치, instance-id, start/stop 및 작업물 보존 안내 헬퍼 |

`scripts/student/upload-capstone.sh`는 런타임이나 e2e의 의존성이 아니라 선택적 SSM 전송 helper입니다. 별도 수강생 패키지 루트에서 실행하며 `TF_DIR`은 이 설정 저장소의 `infrastructure/terraform`을 가리켜야 합니다.

## 수강생 기본 절차

```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
# terraform.tfvars에서 자동 설치 여부와 접속 IP를 강사 공지 기준으로 확인
# AMI는 기존 검증 계열의 최신 DLAMI를 data source로 자동 조회
# 기본값은 user-data 자동 설치 비활성화. SSM 접속 후 install-lab.sh를 직접 실행
# allowed_ingress_cidr는 전체 인바운드를 허용할 본인 공인 IPv4/32로 변경
terraform init
terraform plan
terraform apply -auto-approve
```

Terraform 적용 후 EC2 안에서 설치를 직접 수행한다.

```bash
curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/install-lab.sh | sudo bash
```

강사 운영상 자동 설치가 필요할 때만 `terraform.tfvars`의 `enable_user_data_bootstrap`을 아래처럼 바꾼다. AMI·commit 고정과 이전 변수 제거 방법은 [Terraform 고급 설정](../docs/TERRAFORM-ADVANCED-OPTIONS.md)에 모아 둔다.

```hcl
enable_user_data_bootstrap = true
```

재현 가능한 실측 검증에서는 `lab_setup_repo_raw_url`과 `lab_image_tag`를 같은 40자리 main commit으로 고정한다. `user_data_replace_on_change = false`이므로 이 값은 최초 apply 전에 확정해야 하며, 기존 인스턴스의 변수만 변경해도 bootstrap은 재실행되지 않는다.

이후 매일 시작/종료는 저장소 루트에서 실행한다.

```bash
AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 \
  bash infrastructure/scripts/student/preflight-local.sh

AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 \
  bash infrastructure/scripts/student/start-lab.sh

export INSTANCE_ID=$(AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 \
  bash infrastructure/scripts/student/instance-id.sh)

AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 \
  bash infrastructure/scripts/student/stop-lab.sh
```

## 비용 가드레일

- `g6.xlarge`는 실행 중일 때 비용이 발생한다.
- EC2를 중지하면 인스턴스 실행 비용은 멈추지만 보존된 EBS의 저장 비용은 남는다.
- 이 Terraform은 Budget 알람을 만들지 않는다. 강사가 공지한 종료 시각과 실제 실행 시간을 직접 확인한다.

## 작업물 보존

중지·재시작은 root EBS를 보존하지만 `terraform destroy`나 EC2 종료(terminate)는 root EBS도 삭제한다. 영구 보존할 페이로드와 메모는 최종 삭제 전에 개인 저장소나 승인된 저장 위치로 옮긴다. 기존 ASG 기반 state의 전환은 [Terraform 고급 설정](../docs/TERRAFORM-ADVANCED-OPTIONS.md)을 먼저 확인한다. 여러 실습 EC2가 있으면 helper에 `COURSE_ID`를 지정하고, 조회 결과가 한 대가 아니면 작업을 중단한다.
