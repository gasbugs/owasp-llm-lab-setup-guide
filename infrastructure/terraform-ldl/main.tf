# CUSTOM FILE
# Format reference: https://developer.hashicorp.com/terraform/language
# Terraform configuration language documentation: MPL-2.0

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      ManagedBy = "Terraform"
      Project   = "awsw-preserve-t3-micro"
      Lab       = "owasp-llm-ldl"
    }
  }
}

variable "learner_ipv4_cidr" {
  description = "Public IPv4 /32 of the learner's browser."
  type        = string

  validation {
    condition     = can(cidrnetmask(var.learner_ipv4_cidr)) && endswith(var.learner_ipv4_cidr, "/32")
    error_message = "Enter one public IPv4 address in /32 notation."
  }
}

variable "setup_revision" {
  description = "Verified public setup repository commit to install."
  type        = string
  default     = "07468c2e31a5b9ee3b480423ee8f036c1fa70ac1"

  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.setup_revision))
    error_message = "Use the full 40-character Git commit SHA."
  }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

data "aws_caller_identity" "current" {}

resource "aws_security_group" "ldl" {
  name        = "owasp-llm-ldl"
  description = "LDL browser access"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "LDL browser ports from the learner"
    from_port   = 9010
    to_port     = 9015
    protocol    = "tcp"
    cidr_blocks = [var.learner_ipv4_cidr]
  }

  egress {
    description = "Package repositories, registries and Bedrock APIs"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "ldl" {
  name = "owasp-llm-ldl-ec2"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "model" {
  name = "LdlNovaLite"
  role = aws_iam_role.ldl.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "bedrock:InvokeModel"
      Resource = concat(
        ["arn:aws:bedrock:us-east-1:${data.aws_caller_identity.current.account_id}:inference-profile/us.amazon.nova-lite-v1:0"],
        [for region in ["us-east-1", "us-east-2", "us-west-2"] : "arn:aws:bedrock:${region}::foundation-model/amazon.nova-lite-v1:0"]
      )
    }]
  })
}

resource "aws_iam_instance_profile" "ldl" {
  name = aws_iam_role.ldl.name
  role = aws_iam_role.ldl.name
}

resource "aws_secretsmanager_secret" "grafana" {
  name = "owasp-llm-ldl/grafana-logins"
}

resource "aws_iam_role_policy" "publish_grafana" {
  name = "PublishLdlGrafanaLogins"
  role = aws_iam_role.ldl.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "secretsmanager:PutSecretValue"
      Resource = aws_secretsmanager_secret.grafana.arn
    }]
  })
}

resource "aws_instance" "ldl" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "m6a.large"
  subnet_id                   = sort(data.aws_subnets.default.ids)[0]
  vpc_security_group_ids      = [aws_security_group.ldl.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ldl.name
  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    setup_revision = var.setup_revision
    grafana_secret = aws_secretsmanager_secret.grafana.arn
  })
  tags = { Name = "owasp-llm-ldl" }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  root_block_device {
    encrypted             = true
    volume_type           = "gp3"
    volume_size           = 100
    delete_on_termination = true
    tags                  = { Name = "owasp-llm-ldl" }
  }

  depends_on = [aws_iam_role_policy.model, aws_iam_role_policy.publish_grafana]
}

output "ldl_url" {
  description = "Browser address after cloud-init reports LDL_BOOTSTRAP_READY."
  value       = "http://${aws_instance.ldl.public_ip}:9010/"
}

output "ldl_instance_id" {
  value = aws_instance.ldl.id
}

output "grafana_secret_arn" {
  description = "ARN from which the operator may retrieve Grafana login credentials."
  value       = aws_secretsmanager_secret.grafana.arn
}
