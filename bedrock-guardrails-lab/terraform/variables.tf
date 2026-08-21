variable "region" {
  description = "Bedrock Guardrail을 생성할 AWS 리전"
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "실습 리소스 이름 접두사"
  type        = string
  default     = "owasp-llm-course"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.name_prefix))
    error_message = "name_prefix는 소문자, 숫자와 하이픈만 사용할 수 있습니다."
  }
}
