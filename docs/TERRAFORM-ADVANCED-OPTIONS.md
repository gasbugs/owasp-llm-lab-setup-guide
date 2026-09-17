# Terraform 고급 설정

`terraform.tfvars.example`은 1인 1계정 수강생이 실제로 확인할 값만 담는다. 아래 설정은 강사용 이미지 제작이나 릴리스 재현에 필요할 때만 `terraform.tfvars`에 추가한다.

## 기존 tfvars 이름 변경

이전 예제를 복사한 `terraform.tfvars`가 있다면 `terraform plan` 전에 더 이상 선언되지 않는 다음 변수를 삭제한다.

- `student_ids`, `student_id`
- `course_dates`, `course_start_date`
- `course_budget_usd`, `monthly_budget_usd`, `daily_budget_usd`, `alert_email`
- `enable_auto_stop`, `auto_stop_schedule_mode`, `auto_stop_custom_crons_utc`, `auto_stop_description`

기존 `student_id` 기반 state에서는 IAM·Security Group·Launch Template·ASG의 indexed 주소가 단일 주소로 바뀌고, Budget·SNS·Lambda·EventBridge가 있으면 삭제 대상으로 표시된다. 실행 중인 EC2가 교체될 수 있으므로 작업물을 먼저 보존하고 plan의 삭제·교체 대상을 확인한 뒤 적용한다.

## 자동 설치

기본 예제는 다음 값을 명시해 EC2 생성 후 수강생이 SSM으로 접속하고 설치 과정을 직접 실행하게 한다.

```hcl
enable_user_data_bootstrap = false
```

강사용 환경에서 첫 부팅에 자동 설치하려면 이 값을 바꾼다.

```hcl
enable_user_data_bootstrap = true
```

## 릴리스 commit 고정

강사용 실측은 setup source와 runtime image를 같은 40자리 commit으로 고정한다. 이 값은 최초 `terraform apply` 전에 확정해야 하며 기존 인스턴스의 user-data를 다시 실행하지 않는다.

```hcl
lab_setup_repo_raw_url = "https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/0123456789abcdef0123456789abcdef01234567"
lab_image_namespace    = "gasbugs"
lab_image_tag          = "sha-0123456789abcdef0123456789abcdef01234567"
```

## 강사용 Golden AMI

기본값은 검증된 AWS DLAMI 계열의 최신 이미지를 조회한다. Packer로 만든 AMI 계열을 사용할 때만 조회 조건을 바꾼다.

```hcl
ami_owner_id     = "self"
ami_name_pattern = "owasp-llm-lab-*"
```

## 용량 변경

강의 표준은 `g6.xlarge`와 100GB root volume이다. 다른 인스턴스 타입은 현재 변수 검증이 거부하므로 강사 검증 없이 변경하지 않는다. 더 큰 모델을 추가해 저장 공간이 부족할 때만 100~200GB 범위에서 조정한다.

```hcl
root_volume_size = 150
```

## 종료 정책

Terraform은 자동 중지용 Lambda·EventBridge를 만들지 않는다. 일일 실습이 끝나면 `stop-lab.sh`로 ASG desired capacity를 즉시 0으로 낮춰 EC2와 root EBS를 삭제한다. 전체 강의가 끝나면 운영 중인 계정별 nuke 절차로 잔여 자원을 일괄 삭제하고 결과를 확인한다. 강사용 live validation은 별도 deadline과 EXIT trap으로 직접 EC2 terminate 및 `terraform destroy`를 수행한다.
