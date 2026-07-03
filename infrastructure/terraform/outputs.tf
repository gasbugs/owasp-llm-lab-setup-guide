output "student_role_arns" {
  description = "학생별 IAM Role ARN"
  value       = { for id in var.student_ids : id => aws_iam_role.student[id].arn }
}

output "instance_ids" {
  description = "학생별 EC2 인스턴스 ID"
  value       = { for id in var.student_ids : id => aws_instance.student[id].id }
}

output "public_ips" {
  description = "학생별 EC2 public IP"
  value       = { for id in var.student_ids : id => aws_instance.student[id].public_ip }
}

output "lab_urls" {
  description = "선택적 public IP 직접 접속 URL. 기본 allowed_ingress_cidr=127.0.0.1/32 상태에서는 열리지 않으며, 본인 IP/32로 제한했을 때만 사용."
  value = {
    for id in var.student_ids : id => {
      vuln_rag      = "http://${aws_instance.student[id].public_ip}:8000"
      vuln_agent    = "http://${aws_instance.student[id].public_ip}:8001"
      llmgoat       = "http://${aws_instance.student[id].public_ip}:5000"
      dvla          = "http://${aws_instance.student[id].public_ip}:8501"
      ollama_models = "http://${aws_instance.student[id].public_ip}:11434/api/tags"
    }
  }
}

output "start_commands" {
  description = "학생이 본인 인스턴스 시작하는 명령"
  value = {
    for id in var.student_ids : id => "aws ec2 start-instances --profile ${var.aws_profile} --region ${var.region} --instance-ids ${aws_instance.student[id].id}"
  }
}

output "stop_commands" {
  description = "학생이 본인 인스턴스 중지하는 명령 (강의 끝나면 매일)"
  value = {
    for id in var.student_ids : id => "aws ec2 stop-instances --profile ${var.aws_profile} --region ${var.region} --instance-ids ${aws_instance.student[id].id}"
  }
}

output "ssm_session_commands" {
  description = "학생이 본인 인스턴스에 SSM 접속하기 위한 명령"
  value = {
    for id in var.student_ids : id => "aws ssm start-session --profile ${var.aws_profile} --region ${var.region} --target ${aws_instance.student[id].id}"
  }
}

output "alert_topic_arn" {
  description = "비용 알람 SNS topic ARN"
  value       = aws_sns_topic.alerts.arn
}
