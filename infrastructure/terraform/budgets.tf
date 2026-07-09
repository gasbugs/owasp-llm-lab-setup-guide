################################################################################
# 비용 알람 — 일일 / 강의 전체
################################################################################

resource "aws_sns_topic" "alerts" {
  name = "${local.name_prefix}-alerts"
}

resource "aws_sns_topic_subscription" "alerts_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_budgets_budget" "daily" {
  name              = "${local.name_prefix}-daily"
  budget_type       = "COST"
  limit_amount      = tostring(var.daily_budget_usd)
  limit_unit        = "USD"
  time_unit         = "DAILY"
  time_period_start = "${var.course_dates[0]}_00:00"

  cost_filter {
    name = "TagKeyValue"
    values = [
      format("user:Course$%s", var.course_id),
    ]
  }

  # DAILY budget은 ACTUAL만 지원
  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.alerts.arn]
  }

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_budgets_budget" "course_total" {
  name              = "${local.name_prefix}-total"
  budget_type       = "COST"
  limit_amount      = tostring(var.course_budget_usd)
  limit_unit        = "USD"
  time_unit         = "MONTHLY"
  time_period_start = "${substr(var.course_dates[0], 0, 7)}-01_00:00"

  cost_filter {
    name = "TagKeyValue"
    values = [
      format("user:Course$%s", var.course_id),
    ]
  }

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 90
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.alerts.arn]
  }
}
