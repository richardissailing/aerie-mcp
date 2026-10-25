# Audit lines are bare JSON (see app.py), so metric filters can match their fields.

locals {
  alarms_enabled   = var.alarm_email != null
  metric_namespace = "FalconFleetMcp/${var.name}"
}

resource "aws_cloudwatch_log_metric_filter" "denied" {
  name           = "${var.name}-denied"
  log_group_name = aws_cloudwatch_log_group.lambda.name
  pattern        = "{ ($.audit IS TRUE) && ($.outcome = \"denied\") }"

  metric_transformation {
    name          = "DeniedCalls"
    namespace     = local.metric_namespace
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "actions" {
  name           = "${var.name}-actions"
  log_group_name = aws_cloudwatch_log_group.lambda.name
  # Count action attempts that reached Falcon (refused ones are counted by the denied filter).
  pattern = "{ ($.audit IS TRUE) && ($.outcome != \"denied\") && (($.tool = \"contain_hosts\") || ($.tool = \"lift_containment\") || ($.tool = \"update_alerts\")) }"

  metric_transformation {
    name          = "ActionsExecuted"
    namespace     = local.metric_namespace
    value         = "1"
    default_value = "0"
  }
}

resource "aws_sns_topic" "alarms" {
  count = local.alarms_enabled ? 1 : 0

  name = "${var.name}-alarms"
  # A customer managed key must let cloudwatch.amazonaws.com use it; the AWS managed SNS key cannot be used.
  kms_master_key_id = var.kms_key_arn
}

resource "aws_sns_topic_subscription" "alarm_email" {
  count = local.alarms_enabled ? 1 : 0

  topic_arn = aws_sns_topic.alarms[0].arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

resource "aws_cloudwatch_metric_alarm" "denied" {
  count = local.alarms_enabled ? 1 : 0

  alarm_name          = "${var.name}-denied-calls"
  alarm_description   = "Tool calls refused by the access policy. Check the audit log for the user and tenants."
  namespace           = local.metric_namespace
  metric_name         = "DeniedCalls"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.alarm_denied_threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms[0].arn]
}

resource "aws_cloudwatch_metric_alarm" "actions" {
  count = local.alarms_enabled && var.alarm_on_actions ? 1 : 0

  alarm_name          = "${var.name}-actions-executed"
  alarm_description   = "A containment or alert-update action ran. Check the audit log for who, where and why."
  namespace           = local.metric_namespace
  metric_name         = "ActionsExecuted"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms[0].arn]
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  count = local.alarms_enabled ? 1 : 0

  alarm_name          = "${var.name}-lambda-errors"
  alarm_description   = "The MCP Lambda is failing or timing out."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.this.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms[0].arn]
}
