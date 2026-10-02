# Single On-Demand instance. Stop/start preserves its root EBS and lab state.

locals {
  lab_setup_source_revision = element(
    reverse(split("/", trimsuffix(var.lab_setup_repo_raw_url, "/"))),
    0,
  )
  user_data = templatefile("${path.module}/user-data.sh.tpl", {
    lab_setup_repo_raw_url = var.lab_setup_repo_raw_url
    lab_image_namespace    = var.lab_image_namespace
    lab_image_tag          = var.lab_image_tag
    ollama_model           = var.ollama_model
  })
}

data "aws_ami" "lab_base" {
  most_recent = true
  owners      = [var.ami_owner_id]

  filter {
    name   = "name"
    values = [var.ami_name_pattern]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "student" {
  ami                         = data.aws_ami.lab_base.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.lab[local.instance_availability_zone].id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.student.id]
  iam_instance_profile        = aws_iam_instance_profile.student.name
  user_data                   = var.enable_user_data_bootstrap ? local.user_data : null
  user_data_replace_on_change = false
  monitoring                  = true

  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_size           = var.root_volume_size
    volume_type           = "gp3"
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }

  tags = {
    Name = local.name_prefix
  }
  volume_tags = merge(local.provider_default_tags, {
    Name = "${local.name_prefix}-root"
  })

  lifecycle {
    ignore_changes = [ami]

    precondition {
      condition     = contains(local.available_gpu_zones, local.instance_availability_zone)
      error_message = "선택한 가용 영역에서 ${var.instance_type}을 제공하지 않습니다. availability_zone과 region을 확인하세요."
    }
    precondition {
      condition = (
        !var.enable_user_data_bootstrap ||
        var.lab_image_tag == "latest" ||
        local.lab_setup_source_revision == trimprefix(var.lab_image_tag, "sha-")
      )
      error_message = "commit-pinned bootstrap은 lab_setup_repo_raw_url의 마지막 경로 commit과 lab_image_tag의 sha- commit이 같아야 합니다."
    }
  }
}
