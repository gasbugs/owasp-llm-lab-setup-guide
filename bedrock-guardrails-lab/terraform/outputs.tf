output "guardrail_id" {
  description = "Bedrock Guardrail identifier"
  value       = aws_bedrock_guardrail.course.guardrail_id
}

output "guardrail_version" {
  description = "고정된 Guardrail version"
  value       = aws_bedrock_guardrail_version.course.version
}

output "model_id" {
  description = "실습에서 호출할 Nova Lite inference profile"
  value       = "us.amazon.nova-lite-v1:0"
}
