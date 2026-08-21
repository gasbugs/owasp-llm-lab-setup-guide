resource "aws_bedrock_guardrail" "course" {
  name                      = "${var.name_prefix}-guardrail"
  description               = "OWASP LLM course input and output guardrail"
  blocked_input_messaging   = "요청이 보안 정책에 의해 차단되었습니다."
  blocked_outputs_messaging = "생성 결과가 보안 정책에 의해 차단되었습니다."

  content_policy_config {
    filters_config {
      input_strength  = "HIGH"
      output_strength = "NONE"
      type            = "PROMPT_ATTACK"
    }
  }

  sensitive_information_policy_config {
    regexes_config {
      action      = "ANONYMIZE"
      description = "교육용 API Key 형식"
      name        = "demo-api-key"
      pattern     = "DEMO_API_KEY=[A-Za-z0-9-]+"
    }
  }

  tags = {
    Course    = "owasp-top-10-for-llm"
    ManagedBy = "terraform"
  }
}

resource "aws_bedrock_guardrail_version" "course" {
  description   = "Course validated guardrail version"
  guardrail_arn = aws_bedrock_guardrail.course.guardrail_arn
}
