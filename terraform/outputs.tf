locals {
  mcp_url = "${trimsuffix(coalesce(var.public_base_url, aws_lambda_function_url.this.function_url), "/")}/mcp"
  # Cognito matches redirect URIs exactly, so the CLI must listen on the registered port.
  callback_port = try(regex("^https?://[^/:]+:([0-9]+)", var.oauth_redirect_uris[0])[0], "33418")
}

output "mcp_url" {
  description = "MCP endpoint to give to clients."
  value       = local.mcp_url
}

output "claude_code_command" {
  description = "Add the server to Claude Code (then run /mcp to sign in)."
  value       = "claude mcp add --transport http --client-id ${aws_cognito_user_pool_client.mcp.id} --callback-port ${local.callback_port} falcon ${local.mcp_url}"
}

output "identity_center_app_settings" {
  description = "Values for the customer managed SAML application in IAM Identity Center."
  value = {
    application_acs_url       = "${local.cognito_domain_url}/saml2/idpresponse"
    application_saml_audience = "urn:amazon:cognito:sp:${aws_cognito_user_pool.this.id}"
    attribute_mappings = {
      Subject = var.user_lookup_attribute == "email" ? "$${user:email} (format: emailAddress)" : "<attribute holding the Identity Center username> (format: unspecified)"
      email   = "$${user:email} (format: basic)"
    }
    saml_configured = local.saml_enabled
  }
}

output "lambda_role_arn" {
  description = "Trust this from modules/identity-center-reader when Identity Center is in another account."
  value       = aws_iam_role.lambda.arn
}

output "load_secret_commands" {
  description = <<-EOT
    Run once per credential to store the Falcon API client (values stay out of Terraform state).
    Write {"client_id": "...", "client_secret": "..."} to the file first and delete it afterwards;
    reading from a file keeps the secret out of shell history and the process list.
  EOT
  value = {
    for k, s in aws_secretsmanager_secret.falcon :
    k => "aws secretsmanager put-secret-value --region ${var.aws_region} --secret-id ${s.arn} --secret-string file://falcon-${k}.json && rm falcon-${k}.json"
  }
}
