# Applies the stack against a mocked AWS provider: no credentials needed, nothing is created.
#   cd terraform && terraform test

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/falcon-fleet-mcp-lambda" }
  }
  mock_resource "aws_secretsmanager_secret" {
    defaults = { arn = "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:falcon-fleet-mcp/falcon/x-AbCdEf" }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = { arn = "arn:aws:dynamodb:ap-southeast-2:123456789012:table/falcon-fleet-mcp-config" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:ap-southeast-2:123456789012:log-group:/aws/lambda/falcon-fleet-mcp" }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:ap-southeast-2:123456789012:falcon-fleet-mcp-alarms" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:falcon-fleet-mcp" }
  }
  mock_resource "aws_lambda_function_url" {
    defaults = { function_url = "https://abc123.lambda-url.ap-southeast-2.on.aws/" }
  }
  mock_resource "aws_cognito_user_pool" {
    defaults = {
      id  = "ap-southeast-2_TEST"
      arn = "arn:aws:cognito-idp:ap-southeast-2:123456789012:userpool/ap-southeast-2_TEST"
    }
  }
}

variables {
  lambda_zip_path       = "tests/fixtures/empty.zip"
  cognito_domain_prefix = "test-falcon-mcp"
  identity_store_id     = "d-1234567890"

  falcon_credentials = {
    corp   = {}
    parent = {}
  }
  tenants = {
    corp = { display_name = "Corp", base_url = "us1", credential = "corp", allow_actions = true }
    kid  = { display_name = "Kid", base_url = "US-2", credential = "parent", member_cid = "0123456789ABCDEF0123456789ABCDEF" }
  }
  access_grants = [
    { group = "SOC", tenants = ["*"], role = "reader" },
    { group = "IR", tenants = ["corp"], role = "responder" },
  ]
}

run "defaults" {
  command = apply

  assert {
    condition     = jsondecode(jsondecode(aws_dynamodb_table_item.tenant["kid"].item).doc.S).member_cid == "0123456789abcdef0123456789abcdef"
    error_message = "member_cid should be stored lowercase"
  }
  assert {
    condition     = jsondecode(jsondecode(aws_dynamodb_table_item.tenant["corp"].item).doc.S).member_cid == null
    error_message = "a standalone tenant has no member_cid"
  }
  assert {
    condition = toset(keys(aws_dynamodb_table_item.grant)) == toset([
      "SOC#${substr(sha256(jsonencode(["reader", ["*"]])), 0, 12)}",
      "IR#${substr(sha256(jsonencode(["responder", ["corp"]])), 0, 12)}",
    ])
    error_message = "one item per grant, keyed by content"
  }
  assert {
    condition     = aws_lambda_function.this.environment[0].variables.FANOUT_DEADLINE_SECONDS == "50"
    error_message = "fan-out deadline should be the Lambda timeout minus 10s"
  }
  assert {
    condition     = aws_lambda_function.this.environment[0].variables.ACTIONS_ENABLED == "false"
    error_message = "actions are off by default"
  }
  assert {
    condition     = aws_lambda_function.this.tracing_config[0].mode == "Active"
    error_message = "tracing should be on"
  }
  assert {
    condition     = length(aws_cognito_identity_provider.identity_center) == 0
    error_message = "no SAML provider until the metadata URL is set"
  }
  assert {
    condition     = length(aws_sns_topic.alarms) == 0 && length(aws_cloudwatch_metric_alarm.denied) == 0
    error_message = "alarms are off without alarm_email"
  }
  assert {
    condition     = strcontains(aws_cloudwatch_log_metric_filter.denied.pattern, "denied") && strcontains(aws_cloudwatch_log_metric_filter.actions.pattern, "contain_hosts")
    error_message = "metrics are always published"
  }
  assert {
    condition     = output.claude_code_command != "" && strcontains(output.claude_code_command, "--callback-port 33418")
    error_message = "claude command should use the redirect URI's port"
  }
  assert {
    condition     = strcontains(output.load_secret_commands["corp"], "file://falcon-corp.json")
    error_message = "secrets load from a file, not the command line"
  }
}

run "reordering_grants_changes_no_keys" {
  command = apply

  variables {
    access_grants = [
      { group = "IR", tenants = ["corp"], role = "responder" },
      { group = "SOC", tenants = ["*"], role = "reader" },
    ]
  }

  assert {
    # Same keys the defaults run produced with the opposite order.
    condition = toset(keys(aws_dynamodb_table_item.grant)) == toset([
      "SOC#${substr(sha256(jsonencode(["reader", ["*"]])), 0, 12)}",
      "IR#${substr(sha256(jsonencode(["responder", ["corp"]])), 0, 12)}",
    ])
    error_message = "grant keys must not depend on list order"
  }
}

run "saml_alarms_and_cross_account" {
  command = apply

  variables {
    identity_center_saml_metadata_url = "https://portal.sso.ap-southeast-2.amazonaws.com/saml/metadata/abc"
    alarm_email                       = "soc@example.com"
    identity_store_role_arn           = "arn:aws:iam::210987654321:role/falcon-fleet-mcp-identity-reader"
    actions_enabled                   = true
    oauth_redirect_uris               = ["http://localhost:40000/callback"]
  }

  assert {
    condition     = length(aws_cognito_identity_provider.identity_center) == 1
    error_message = "SAML provider is created once the metadata URL is set"
  }
  assert {
    condition     = length(aws_cloudwatch_metric_alarm.denied) == 1 && length(aws_cloudwatch_metric_alarm.actions) == 1 && length(aws_cloudwatch_metric_alarm.lambda_errors) == 1
    error_message = "all three alarms exist when alarm_email is set"
  }
  assert {
    condition     = aws_lambda_function.this.environment[0].variables.IDENTITY_STORE_ROLE_ARN == var.identity_store_role_arn
    error_message = "the Lambda assumes the cross-account reader role"
  }
  assert {
    condition     = strcontains(output.claude_code_command, "--callback-port 40000")
    error_message = "callback port follows the first redirect URI"
  }
}

run "rejects_non_falcon_base_url" {
  command = plan
  variables {
    tenants = {
      corp = { display_name = "Corp", base_url = "api.crowdstrike.com.evil.com", credential = "corp" }
    }
    access_grants = [{ group = "SOC", tenants = ["*"], role = "reader" }]
  }
  expect_failures = [var.tenants]
}

run "rejects_duplicate_child" {
  command = plan
  variables {
    tenants = {
      a = { display_name = "A", base_url = "us2", credential = "parent", member_cid = "0123456789abcdef0123456789abcdef" }
      b = { display_name = "B", base_url = "us2", credential = "parent", member_cid = "0123456789ABCDEF0123456789ABCDEF" }
    }
    access_grants = [{ group = "SOC", tenants = ["*"], role = "reader" }]
  }
  expect_failures = [var.tenants]
}

run "rejects_unknown_credential" {
  command = plan
  variables {
    tenants = {
      a = { display_name = "A", base_url = "us1", credential = "nope" }
    }
    access_grants = [{ group = "SOC", tenants = ["*"], role = "reader" }]
  }
  expect_failures = [var.tenants]
}

run "rejects_grant_for_unknown_tenant" {
  command = plan
  variables {
    access_grants = [{ group = "SOC", tenants = ["missing"], role = "reader" }]
  }
  expect_failures = [var.access_grants]
}

run "rejects_bad_role" {
  command = plan
  variables {
    access_grants = [{ group = "SOC", tenants = ["*"], role = "admin" }]
  }
  expect_failures = [var.access_grants]
}

run "rejects_short_lambda_timeout" {
  command = plan
  variables {
    lambda_timeout_seconds = 10
  }
  expect_failures = [var.lambda_timeout_seconds]
}
