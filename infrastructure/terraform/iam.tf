################################################################################
# 수강생 IAM — 수강생당 1 Role
#
# 격리:
#   - SSM Session Manager로 자기 인스턴스 접속만 허용 (Tag 조건)
#   - CloudWatch Logs 본인 log group만
#   - 그 외 EC2/IAM/Lambda/S3 등 모든 권한 없음
#
# 작업물 보존:
#   - 강사 계정 S3 사용 X. 수강생이 개인 GitHub 작업 repo에 git push로 보존.
################################################################################

data "aws_iam_policy_document" "student_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "student" {
  for_each           = toset(var.student_ids)
  name               = "${local.name_prefix}-role-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.student_assume.json

  tags = {
    Student = each.key
  }
}

# SSM Session Manager 기본 (인바운드 SSH 없이 접근)
resource "aws_iam_role_policy_attachment" "student_ssm" {
  for_each   = toset(var.student_ids)
  role       = aws_iam_role.student[each.key].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# CloudWatch Logs — SSM Agent와 선택적 bootstrap 로그용
resource "aws_iam_role_policy" "student_logs" {
  for_each = toset(var.student_ids)
  name     = "cloudwatch-logs"
  role     = aws_iam_role.student[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "arn:${data.aws_partition.current.partition}:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${local.name_prefix}-*"
    }]
  })
}

resource "aws_iam_instance_profile" "student" {
  for_each = toset(var.student_ids)
  name     = "${local.name_prefix}-profile-${each.key}"
  role     = aws_iam_role.student[each.key].name
}
