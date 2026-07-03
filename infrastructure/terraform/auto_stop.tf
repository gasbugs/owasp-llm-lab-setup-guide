################################################################################
# Night auto-stop — EventBridge invokes Lambda from 17:30 KST to next-day 08:30 KST
################################################################################

locals {
  auto_stop_resource_prefix = substr("${local.name_prefix}-auto-stop", 0, 48)
  auto_stop_schedules = var.auto_stop_cron_utc == null ? var.auto_stop_crons_utc : {
    legacy = var.auto_stop_cron_utc
  }
}

data "archive_file" "auto_stop_lambda" {
  count = var.enable_auto_stop ? 1 : 0

  type        = "zip"
  source_file = "${path.module}/lambda/auto_stop.py"
  output_path = "${path.module}/.terraform/auto-stop-lambda.zip"
}

data "aws_iam_policy_document" "auto_stop_lambda_assume" {
  count = var.enable_auto_stop ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "auto_stop_lambda" {
  count = var.enable_auto_stop ? 1 : 0

  name               = "${local.auto_stop_resource_prefix}-lambda"
  assume_role_policy = data.aws_iam_policy_document.auto_stop_lambda_assume[0].json
}

resource "aws_iam_role_policy_attachment" "auto_stop_lambda_basic" {
  count = var.enable_auto_stop ? 1 : 0

  role       = aws_iam_role.auto_stop_lambda[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "auto_stop_lambda_ec2" {
  count = var.enable_auto_stop ? 1 : 0

  statement {
    actions = [
      "ec2:DescribeInstances",
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "ec2:StopInstances",
    ]
    resources = [for instance in aws_instance.student : instance.arn]
  }
}

resource "aws_iam_role_policy" "auto_stop_lambda_ec2" {
  count = var.enable_auto_stop ? 1 : 0

  name   = "ec2-auto-stop"
  role   = aws_iam_role.auto_stop_lambda[0].id
  policy = data.aws_iam_policy_document.auto_stop_lambda_ec2[0].json
}

resource "aws_lambda_function" "auto_stop" {
  count = var.enable_auto_stop ? 1 : 0

  function_name    = local.auto_stop_resource_prefix
  description      = "Stops running EC2 lab instances tagged Course=${var.course_id}"
  role             = aws_iam_role.auto_stop_lambda[0].arn
  handler          = "auto_stop.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.auto_stop_lambda[0].output_path
  source_code_hash = data.archive_file.auto_stop_lambda[0].output_base64sha256
  timeout          = 60

  environment {
    variables = {
      COURSE_ID = var.course_id
      DRY_RUN   = "false"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.auto_stop_lambda_basic,
    aws_iam_role_policy.auto_stop_lambda_ec2,
  ]
}

resource "aws_cloudwatch_event_rule" "auto_stop" {
  for_each = var.enable_auto_stop ? local.auto_stop_schedules : {}

  name                = "${local.auto_stop_resource_prefix}-${substr(md5(each.key), 0, 8)}"
  description         = "${var.auto_stop_description}: ${each.value}"
  schedule_expression = each.value
}

resource "aws_cloudwatch_event_target" "auto_stop" {
  for_each = var.enable_auto_stop ? local.auto_stop_schedules : {}

  rule      = aws_cloudwatch_event_rule.auto_stop[each.key].name
  target_id = "auto-stop-lambda"
  arn       = aws_lambda_function.auto_stop[0].arn
}

resource "aws_lambda_permission" "allow_eventbridge_auto_stop" {
  for_each = var.enable_auto_stop ? local.auto_stop_schedules : {}

  statement_id  = "AllowExecutionFromEventBridgeAutoStop${replace(each.key, "-", "")}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auto_stop[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.auto_stop[each.key].arn
}
