# Cognito is only the OAuth front door: users never get Cognito passwords. Sign-in is
# federated (SAML) to IAM Identity Center, and the MCP server resolves group membership
# from the Identity Store on each token.

resource "aws_cognito_user_pool" "this" {
  name                = var.name
  deletion_protection = "ACTIVE"
  user_pool_tier      = "ESSENTIALS"

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  schema {
    name                = "email"
    attribute_data_type = "String"
    mutable             = true
    required            = false

    string_attribute_constraints {
      min_length = 0
      max_length = 2048
    }
  }
}

resource "aws_cognito_user_pool_domain" "this" {
  domain                = var.cognito_domain_prefix
  user_pool_id          = aws_cognito_user_pool.this.id
  managed_login_version = 1 # classic hosted UI; users are sent straight to Identity Center
}

resource "aws_cognito_identity_provider" "identity_center" {
  count = local.saml_enabled ? 1 : 0

  user_pool_id  = aws_cognito_user_pool.this.id
  provider_name = local.idp_name
  provider_type = "SAML"

  provider_details = {
    MetadataURL = var.identity_center_saml_metadata_url
    IDPSignout  = "false"
  }

  attribute_mapping = {
    email = "email"
  }
}

resource "aws_cognito_user_pool_client" "mcp" {
  name         = "${var.name}-mcp-clients"
  user_pool_id = aws_cognito_user_pool.this.id

  # Public client: MCP clients run on laptops and cannot keep a secret; PKCE protects the code.
  generate_secret                      = false
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  callback_urls                        = var.oauth_redirect_uris
  supported_identity_providers         = local.saml_enabled ? [local.idp_name] : ["COGNITO"]
  explicit_auth_flows                  = ["ALLOW_REFRESH_TOKEN_AUTH"]

  access_token_validity  = var.access_token_minutes
  id_token_validity      = var.access_token_minutes
  refresh_token_validity = var.refresh_token_hours
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "hours"
  }

  enable_token_revocation       = true
  prevent_user_existence_errors = "ENABLED"

  depends_on = [aws_cognito_identity_provider.identity_center]
}
