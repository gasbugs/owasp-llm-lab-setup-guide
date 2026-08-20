################################################################################
# 수강생별 Auto Scaling Group — 여러 AZ 중 가용 용량이 있는 곳에 1대 배치
#
# ASG desired capacity를 0/1로 조정하므로 종료 시 인스턴스와 root EBS는 삭제된다.
# 다시 시작하면 AMI와 선택적 user-data로 새 인스턴스를 만든다.
################################################################################

locals {
  lab_setup_source_revision = element(
    reverse(split("/", trimsuffix(var.lab_setup_repo_raw_url, "/"))),
    0,
  )
  user_data = templatefile("${path.module}/user-data.sh.tpl", {
    lab_setup_repo_raw_url = var.lab_setup_repo_raw_url
    lab_image_namespace    = var.lab_image_namespace
    lab_image_tag          = var.lab_image_tag
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

resource "aws_launch_template" "student" {
  for_each = toset(var.student_ids)

  name_prefix   = "${local.name_prefix}-${each.key}-"
  image_id      = data.aws_ami.lab_base.id
  instance_type = var.instance_type
  user_data     = var.enable_user_data_bootstrap ? base64encode(local.user_data) : null

  iam_instance_profile {
    name = aws_iam_instance_profile.student[each.key].name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.student[each.key].id]
  }

  block_device_mappings {
    device_name = data.aws_ami.lab_base.root_device_name

    ebs {
      delete_on_termination = true
      encrypted             = true
      volume_size           = var.root_volume_size
      volume_type           = "gp3"
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name    = "${local.name_prefix}-${each.key}"
      Student = each.key
      Course  = var.course_id
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name    = "${local.name_prefix}-${each.key}-root"
      Student = each.key
      Course  = var.course_id
    }
  }

  lifecycle {
    create_before_destroy = true

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

resource "aws_autoscaling_group" "student" {
  for_each = toset(var.student_ids)

  name                             = "${local.name_prefix}-asg-${each.key}"
  min_size                         = 0
  max_size                         = 1
  desired_capacity                 = 1
  health_check_type                = "EC2"
  health_check_grace_period        = 300
  ignore_failed_scaling_activities = true
  vpc_zone_identifier              = values(aws_subnet.lab)[*].id
  wait_for_capacity_timeout        = "20m"

  launch_template {
    id      = aws_launch_template.student[each.key].id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${local.name_prefix}-${each.key}"
    propagate_at_launch = true
  }

  tag {
    key                 = "Student"
    value               = each.key
    propagate_at_launch = true
  }

  tag {
    key                 = "Course"
    value               = var.course_id
    propagate_at_launch = true
  }

  lifecycle {
    ignore_changes = [desired_capacity]
  }

  depends_on = [
    aws_cloudwatch_event_target.auto_stop,
    aws_lambda_permission.allow_eventbridge_auto_stop,
  ]
}
