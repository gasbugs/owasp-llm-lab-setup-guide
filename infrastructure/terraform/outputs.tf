output "ami_id" {
  description = "Terraform이 선택한 base AMI ID"
  value       = data.aws_ami.lab_base.id
}

output "ami_name" {
  description = "Terraform이 선택한 base AMI name"
  value       = data.aws_ami.lab_base.name
}

output "student_role_arns" {
  description = "수강생별 IAM Role ARN"
  value       = { for id in var.student_ids : id => aws_iam_role.student[id].arn }
}

output "instance_ids" {
  description = "수강생별 EC2 인스턴스 ID"
  value       = { for id in var.student_ids : id => aws_instance.student[id].id }
}

output "public_ips" {
  description = "수강생별 EC2 public IP"
  value       = { for id in var.student_ids : id => aws_instance.student[id].public_ip }
}

output "lab_urls" {
  description = "선택적 public IP 직접 접속 URL. 기본 allowed_ingress_cidr=127.0.0.1/32 상태에서는 열리지 않으며, 본인 IP/32로 제한했을 때만 사용."
  value = {
    for id in var.student_ids : id => {
      portal        = "http://${aws_instance.student[id].public_ip}:8080"
      day1_vuln_rag = "http://${aws_instance.student[id].public_ip}:8000"
      day2_vuln_rag = "http://${aws_instance.student[id].public_ip}:8010"
      day3_vuln_rag = "http://${aws_instance.student[id].public_ip}:8011"
      day4_vuln_rag = "http://${aws_instance.student[id].public_ip}:8012"
      day5_vuln_rag = "http://${aws_instance.student[id].public_ip}:8013"
      vuln_agent    = "http://${aws_instance.student[id].public_ip}:8001"
      fake_registry = "http://${aws_instance.student[id].public_ip}:8002/api/v1/models"
      llmgoat       = "http://${aws_instance.student[id].public_ip}:5000"
      cve_analyst   = "http://${aws_instance.student[id].public_ip}:5050"
      dvla          = "http://${aws_instance.student[id].public_ip}:8501"
      ollama_models = "http://${aws_instance.student[id].public_ip}:11434/api/tags"
    }
  }
}

output "manual_install_commands" {
  description = "SSM 접속 후 EC2 안에서 실행하는 수동 실습 환경 설치 명령"
  value = {
    for id in var.student_ids : id => "curl -fsSL ${var.lab_setup_repo_raw_url}/infrastructure/scripts/student/install-lab.sh | sudo bash"
  }
}

output "start_commands" {
  description = "수강생이 본인 인스턴스 시작하는 명령"
  value = {
    for id in var.student_ids : id => "aws ec2 start-instances --profile ${var.aws_profile} --region ${var.region} --instance-ids ${aws_instance.student[id].id}"
  }
}

output "stop_commands" {
  description = "수강생이 본인 인스턴스 중지하는 명령 (강의 끝나면 매일)"
  value = {
    for id in var.student_ids : id => "aws ec2 stop-instances --profile ${var.aws_profile} --region ${var.region} --instance-ids ${aws_instance.student[id].id}"
  }
}

output "ssm_session_commands" {
  description = "수강생이 본인 인스턴스에 SSM 접속하기 위한 명령"
  value = {
    for id in var.student_ids : id => "aws ssm start-session --profile ${var.aws_profile} --region ${var.region} --target ${aws_instance.student[id].id}"
  }
}

output "alert_topic_arn" {
  description = "비용 알람 SNS topic ARN"
  value       = aws_sns_topic.alerts.arn
}

output "auto_stop_schedule" {
  description = "자동 EC2 중지 스케줄 map. 기본 모드는 daily_1730."
  value       = var.enable_auto_stop ? local.auto_stop_schedules : null
}
