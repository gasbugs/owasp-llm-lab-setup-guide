################################################################################
# 학생별 EC2 인스턴스 — for_each로 학생 수만큼 1대씩
#
# 설계 (1인 1계정 모델):
#   - On-Demand GPU 인스턴스 1대/학생
#   - 학생이 직접 `aws ec2 start-instances` / `stop-instances`로 ON/OFF
#   - Stop 시 EC2 시간당 요금 0. EBS 디스크 비용만 발생 (gp3 100GB 기준)
#   - terminate 안 하므로 EBS·작업물 그대로 보존. 다음 start 시 어제 상태 그대로
#   - 기본값은 수동 설치. 필요 시 user-data 자동 설치를 명시적으로 켤 수 있음
#   - 설치 후에는 컨테이너 systemd unit으로 다음 start 시 자동 시작
#
# 작업물 추가 보존 (선택):
#   학생이 개인 GitHub 작업 repo에 push로 강의 종료 후에도 보존.
################################################################################

locals {
  user_data = templatefile("${path.module}/user-data.sh.tpl", {
    lab_setup_repo_raw_url = var.lab_setup_repo_raw_url
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
  for_each = toset(var.student_ids)

  ami                    = data.aws_ami.lab_base.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.lab.id
  vpc_security_group_ids = [aws_security_group.student[each.key].id]
  iam_instance_profile   = aws_iam_instance_profile.student[each.key].name

  associate_public_ip_address = true # IGW 통한 인터넷 직접 (apt/podman/ollama pull)

  root_block_device {
    volume_size           = var.root_volume_size
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
    tags = {
      Student = each.key
      Course  = var.course_id
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }

  monitoring = true

  user_data                   = var.enable_user_data_bootstrap ? local.user_data : null
  user_data_replace_on_change = false # user-data 변경해도 인스턴스 재생성 X (학생 데이터 보존)

  tags = {
    Name    = "${local.name_prefix}-${each.key}"
    Student = each.key
    Course  = var.course_id
  }

  lifecycle {
    # 인스턴스 stop/start로 state가 바뀌어도 terraform이 재생성하지 않도록
    ignore_changes = [
      ami, # 최신 AMI가 갱신되어도 기존 학생 인스턴스를 자동 교체하지 않음
    ]
  }
}
