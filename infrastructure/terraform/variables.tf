variable "region" {
  description = "AWS 리전. G 계열 GPU 인스턴스 가용성 확인 후 선택."
  type        = string
  default     = "us-east-1"
  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", var.region))
    error_message = "region은 us-east-1 같은 AWS 리전 형식이어야 합니다."
  }
}

variable "aws_profile" {
  description = "로컬 AWS CLI profile 이름"
  type        = string
  default     = "owasp-llm"
  validation {
    condition     = can(regex("^[A-Za-z0-9_.@-]+$", var.aws_profile))
    error_message = "aws_profile은 AWS CLI profile 이름으로 사용할 수 있는 문자만 포함해야 합니다."
  }
}

variable "course_id" {
  description = "강의 식별자. 리소스 이름 prefix로 사용. 예: 2026-06-cohort-a"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]{3,40}$", var.course_id))
    error_message = "course_id는 소문자/숫자/하이픈만, 3~40자로 입력하세요."
  }
}

variable "student_ids" {
  description = "수강생 ID 목록. 영문/숫자/하이픈만 사용. 인스턴스 태그·IAM 이름에 그대로 들어감"
  type        = list(string)
  validation {
    condition     = length(var.student_ids) > 0 && alltrue([for id in var.student_ids : can(regex("^[a-z0-9-]{2,30}$", id))])
    error_message = "student_ids는 소문자/숫자/하이픈만, 2~30자."
  }
}

variable "course_dates" {
  description = "강의 일자(연속 5일 가정). 예: [\"2026-06-10\", \"2026-06-11\", ...]. 비용 산정·태그용."
  type        = list(string)
  validation {
    condition     = length(var.course_dates) == 5 && alltrue([for d in var.course_dates : can(regex("^20[0-9]{2}-[0-9]{2}-[0-9]{2}$", d))])
    error_message = "course_dates는 YYYY-MM-DD 형식의 5개 날짜여야 합니다."
  }
}

variable "enable_user_data_bootstrap" {
  description = "true이면 EC2 최초 부팅 시 install-lab.sh를 user-data로 자동 실행한다. 기본값 false는 수강생이 SSM 접속 후 직접 설치 절차를 수행하는 방식이다."
  type        = bool
  default     = false
}

variable "lab_setup_repo_raw_url" {
  description = "install-lab.sh와 fake-registry/server.py를 내려받을 GitHub raw URL prefix. fork나 특정 브랜치를 쓰는 경우 override한다."
  type        = string
  default     = "https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main"
  validation {
    condition     = can(regex("^https://", var.lab_setup_repo_raw_url))
    error_message = "lab_setup_repo_raw_url은 https:// 로 시작해야 합니다."
  }
}

variable "ami_name_pattern" {
  description = "EC2 base AMI name pattern. 기본값은 기존 검증 계열인 Deep Learning OSS Nvidia Driver AMI GPU PyTorch 2.11 Ubuntu 24.04 최신 이미지를 조회한다."
  type        = string
  default     = "Deep Learning OSS Nvidia Driver AMI GPU PyTorch 2.11 (Ubuntu 24.04)*"
  validation {
    condition     = length(trimspace(var.ami_name_pattern)) >= 3
    error_message = "ami_name_pattern은 최소 3자 이상이어야 합니다."
  }
}

variable "ami_owner_id" {
  description = "AMI owner ID. AWS Deep Learning AMI owner 기본값은 898082745236. 본인 계정 Packer AMI를 쓰려면 self를 입력한다."
  type        = string
  default     = "898082745236"
  validation {
    condition     = var.ami_owner_id == "self" || can(regex("^[0-9]{12}$", var.ami_owner_id))
    error_message = "ami_owner_id는 12자리 AWS account ID 또는 self여야 합니다."
  }
}

variable "instance_type" {
  description = "EC2 인스턴스 타입. 비용 절감 기본값은 g4dn.xlarge(T4 16GB), 안정 운영 권장은 g6.xlarge(L4 24GB)."
  type        = string
  default     = "g4dn.xlarge"
  validation {
    condition     = contains(["g4dn.xlarge", "g6.xlarge"], var.instance_type)
    error_message = "instance_type은 비용 절감형 g4dn.xlarge 또는 안정 운영형 g6.xlarge 중 하나로 설정하세요."
  }
}

variable "root_volume_size" {
  description = "EBS root 볼륨 크기(GB). 모델 weights·컨테이너 이미지·실습 패키지 포함 → 100GB 권장."
  type        = number
  default     = 100
  validation {
    condition     = var.root_volume_size >= 100 && var.root_volume_size <= 200
    error_message = "root_volume_size는 100~200GB 범위로 설정하세요."
  }
}

variable "allowed_ingress_cidr" {
  description = "실습 웹 포트 직접 접근 허용 CIDR. 기본값은 외부 직접 접속을 사실상 닫고 SSM 포트포워딩을 사용한다. 직접 접속이 필요할 때만 본인 IP/32로 변경."
  type        = string
  default     = "127.0.0.1/32"
  validation {
    condition     = can(cidrhost(var.allowed_ingress_cidr, 0)) && var.allowed_ingress_cidr != "0.0.0.0/0" && var.allowed_ingress_cidr != "::/0"
    error_message = "allowed_ingress_cidr는 127.0.0.1/32 또는 본인 공인 IP/32처럼 제한된 CIDR이어야 하며 전체 공개 CIDR은 금지합니다."
  }
}

# 자동 시작/종료 스케줄 변수는 없다.
# 학생이 직접 `aws ec2 start-instances` / `stop-instances`로 ON/OFF한다.

variable "daily_budget_usd" {
  description = "일일 비용 알람 임계값(USD)"
  type        = number
  default     = 200
  validation {
    condition     = var.daily_budget_usd > 0 && var.daily_budget_usd <= 10000
    error_message = "daily_budget_usd는 0보다 크고 10000 이하로 설정하세요."
  }
}

variable "course_budget_usd" {
  description = "강의 전체 비용 알람 임계값(USD)"
  type        = number
  default     = 1500
  validation {
    condition     = var.course_budget_usd > 0 && var.course_budget_usd <= 100000
    error_message = "course_budget_usd는 0보다 크고 100000 이하로 설정하세요."
  }
}

variable "alert_email" {
  description = "비용 알람·운영 알람을 받을 이메일"
  type        = string
  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email은 알림을 받을 이메일 주소 형식이어야 합니다."
  }
}

# backup_retention_days 변수 제거 — S3 백업 자체를 안 씀
