provider "aws" {
  region  = var.region
  profile = var.aws_profile

  default_tags {
    tags = local.common_tags
  }
}

locals {
  common_tags = {
    Project   = "owasp-top-10-for-llm"
    Course    = var.course_id
    ManagedBy = "Terraform"
  }

  name_prefix = "owasp-llm-${var.course_id}"

  # 실제로 설치되는 앱만 허용한다. 8003~8009 같은 미사용 포트는 열지 않는다.
  lab_app_ports = toset([8000, 8001, 8002, 8010, 8011, 8012, 8013])
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
