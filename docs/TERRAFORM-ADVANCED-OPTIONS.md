# Terraform 고급 설정

`terraform.tfvars.example`은 1인 1계정 수강생이 실제로 확인할 값만 담는다. 아래 설정은 강사용 이미지 제작이나 릴리스 재현에 필요할 때만 `terraform.tfvars`에 추가한다.

## 기존 tfvars 이름 변경

이전 예제를 복사한 `terraform.tfvars`가 있다면 `terraform plan` 전에 수강생 목록을 ID 하나로 바꾸고, 더 이상 선언되지 않는 날짜·월간 Budget·자동 중지 변수는 삭제한다.

```hcl
# 변경 전: student_ids = ["student01"]
student_id = "student01"
```

삭제할 수 있는 이전 변수 이름은 `course_dates`, `course_start_date`, `course_budget_usd`, `monthly_budget_usd`, `enable_auto_stop`, `auto_stop_schedule_mode`, `auto_stop_custom_crons_utc`, `auto_stop_description`이다.

`student01` 같은 기존 ID를 유지하면 EC2·ASG·IAM의 Terraform resource 주소는 바뀌지 않는다. 반면 이전 Terraform state에 자동 중지 Lambda·EventBridge와 월간 Budget이 있으면 새 plan에는 해당 자원 삭제가 표시된다. 이는 현재 운영 정책에 맞는 변경이므로 정확한 대상인지 확인한 뒤 적용한다.

## 자동 설치

기본값은 EC2 생성 후 수강생이 SSM으로 접속해 설치 과정을 직접 실행하는 방식이다. 첫 부팅에 자동 설치하려면 다음 값을 추가한다.

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
