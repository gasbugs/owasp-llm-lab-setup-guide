provider "aws" {
  region  = var.region
  profile = var.aws_profile

  default_tags {
    # Provider configuration must contain only plan-time-known values.
    tags = local.provider_default_tags
  }
}

locals {
  provider_default_tags = {
    Project   = "owasp-top-10-for-llm"
    Course    = var.course_id
    ManagedBy = "Terraform"
  }

  name_prefix = "owasp-llm-${var.course_id}"

  # 실제로 설치되는 앱만 허용한다. 8003~8009 같은 미사용 포트는 열지 않는다.
  # 18080은 LLM08 학습자 미니 앱이며 allowed_ingress_cidr /32로만 접근한다.
  lab_app_ports = toset([8000, 8001, 8002, 8010, 8011, 8012, 8013, 18080])

  # Module 08 관측 UI/API는 실습자의 공인 IPv4 /32에서만 직접 접근한다.
  module08_observability_ports = toset([
    3001, 3100, 3200, 4318, 8014, 8015,
    8099, 9009, 9090, 9093, 9400, 12345,
  ])
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
