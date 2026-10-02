output "ami_id" {
  description = "Terraform이 선택한 base AMI ID"
  value       = data.aws_ami.lab_base.id
}

output "ami_name" {
  description = "Terraform이 선택한 base AMI name"
  value       = data.aws_ami.lab_base.name
}

output "availability_zones" {
  description = "GPU 인스턴스 타입을 제공하는 가용 영역 목록 (실시간 용량 보장 아님)"
  value       = local.selected_availability_zones
}

output "instance_id" {
  description = "중지·재시작 때 재사용하는 단일 EC2 ID"
  value       = aws_instance.student.id
}

output "instance_lookup_command" {
  description = "현재 단일 EC2 인스턴스 ID 조회 명령"
  value       = "aws ec2 describe-instances --profile ${var.aws_profile} --region ${var.region} --filters Name=tag:Project,Values=owasp-top-10-for-llm Name=tag:Course,Values=${var.course_id} Name=instance-state-name,Values=pending,running --query 'Reservations[].Instances[].InstanceId' --output text"
}

output "manual_install_command" {
  description = "SSM 접속 후 EC2 안에서 실행하는 수동 실습 환경 설치 명령"
  value       = "curl -fsSL ${var.lab_setup_repo_raw_url}/infrastructure/scripts/student/install-lab.sh | sudo bash"
}

output "public_ip_lookup_command" {
  description = "현재 단일 EC2 public IP 조회 명령"
  value       = "aws ec2 describe-instances --profile ${var.aws_profile} --region ${var.region} --filters Name=tag:Project,Values=owasp-top-10-for-llm Name=tag:Course,Values=${var.course_id} Name=instance-state-name,Values=pending,running --query 'Reservations[].Instances[].PublicIpAddress' --output text"
}

output "ssm_session_command" {
  description = "Terraform이 관리하는 EC2에 SSM 셸로 접속하는 명령"
  value       = "aws ssm start-session --profile ${var.aws_profile} --region ${var.region} --target ${aws_instance.student.id}"
}

output "start_command" {
  description = "기존 EC2를 다시 시작하는 명령"
  value       = "aws ec2 start-instances --profile ${var.aws_profile} --region ${var.region} --instance-ids ${aws_instance.student.id}"
}

output "stop_command" {
  description = "EC2를 중지하고 root EBS를 보존하는 명령 (EBS 비용은 계속 발생)"
  value       = "aws ec2 stop-instances --profile ${var.aws_profile} --region ${var.region} --instance-ids ${aws_instance.student.id}"
}

output "instance_role_arn" {
  description = "단일 실습 EC2 IAM Role ARN"
  value       = aws_iam_role.student.arn
}
