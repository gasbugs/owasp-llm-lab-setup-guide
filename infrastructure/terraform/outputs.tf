output "alert_topic_arn" {
  description = "비용 알람 SNS topic ARN"
  value       = aws_sns_topic.alerts.arn
}

output "ami_id" {
  description = "Terraform이 선택한 base AMI ID"
  value       = data.aws_ami.lab_base.id
}

output "ami_name" {
  description = "Terraform이 선택한 base AMI name"
  value       = data.aws_ami.lab_base.name
}

output "auto_stop_schedule" {
  description = "자동 ASG 축소 스케줄 map. 기본 모드는 daily_1800."
  value       = var.enable_auto_stop ? local.auto_stop_schedules : null
}

output "availability_zones" {
  description = "ASG가 인스턴스를 배치할 수 있는 가용 영역 목록"
  value       = local.selected_availability_zones
}

output "autoscaling_group_names" {
  description = "수강생별 Auto Scaling Group 이름"
  value       = { for id in var.student_ids : id => aws_autoscaling_group.student[id].name }
}

output "instance_lookup_commands" {
  description = "수강생별 현재 EC2 인스턴스 ID 조회 명령"
  value = {
    for id in var.student_ids : id => "aws ec2 describe-instances --profile ${var.aws_profile} --region ${var.region} --filters Name=tag:Course,Values=${var.course_id} Name=tag:Student,Values=${id} Name=instance-state-name,Values=pending,running --query 'Reservations[].Instances[].InstanceId' --output text"
  }
}

output "manual_install_commands" {
  description = "SSM 접속 후 EC2 안에서 실행하는 수동 실습 환경 설치 명령"
  value = {
    for id in var.student_ids : id => "curl -fsSL ${var.lab_setup_repo_raw_url}/infrastructure/scripts/student/install-lab.sh | sudo bash"
  }
}

output "public_ip_lookup_commands" {
  description = "수강생별 현재 EC2 public IP 조회 명령"
  value = {
    for id in var.student_ids : id => "aws ec2 describe-instances --profile ${var.aws_profile} --region ${var.region} --filters Name=tag:Course,Values=${var.course_id} Name=tag:Student,Values=${id} Name=instance-state-name,Values=pending,running --query 'Reservations[].Instances[].PublicIpAddress' --output text"
  }
}

output "ssm_session_commands" {
  description = "현재 ASG 인스턴스 ID를 조회해 SSM 접속하는 명령"
  value = {
    for id in var.student_ids : id => "aws ssm start-session --profile ${var.aws_profile} --region ${var.region} --target $(aws ec2 describe-instances --profile ${var.aws_profile} --region ${var.region} --filters Name=tag:Course,Values=${var.course_id} Name=tag:Student,Values=${id} Name=instance-state-name,Values=running --query 'Reservations[0].Instances[0].InstanceId' --output text)"
  }
}

output "start_commands" {
  description = "수강생별 ASG desired capacity를 1로 올려 새 인스턴스를 생성하는 명령"
  value = {
    for id in var.student_ids : id => "aws autoscaling update-auto-scaling-group --profile ${var.aws_profile} --region ${var.region} --auto-scaling-group-name ${aws_autoscaling_group.student[id].name} --min-size 0 --max-size 1 --desired-capacity 1"
  }
}

output "stop_commands" {
  description = "수강생별 ASG desired capacity를 0으로 내려 인스턴스를 삭제하는 명령"
  value = {
    for id in var.student_ids : id => "aws autoscaling update-auto-scaling-group --profile ${var.aws_profile} --region ${var.region} --auto-scaling-group-name ${aws_autoscaling_group.student[id].name} --min-size 0 --max-size 1 --desired-capacity 0"
  }
}

output "student_role_arns" {
  description = "수강생별 IAM Role ARN"
  value       = { for id in var.student_ids : id => aws_iam_role.student[id].arn }
}
