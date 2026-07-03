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
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
