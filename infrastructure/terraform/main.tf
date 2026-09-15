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
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
