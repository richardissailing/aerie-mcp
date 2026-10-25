variable "aws_region" {
  description = "Region for the Lambda, Cognito and config table."
  type        = string
  default     = "ap-southeast-2" # Sydney
}

variable "name" {
  description = "Name prefix for every resource."
  type        = string
  default     = "falcon-fleet-mcp"
}

variable "tags" {
  description = "Extra tags applied to all resources."
  type        = map(string)
  default     = {}
}

# --- CrowdStrike tenants ------------------------------------------------------------------

variable "falcon_credentials" {
  description = <<-EOT
    Falcon API clients, keyed by a short name. Terraform creates an empty Secrets Manager
    secret for each; you load {"client_id": "...", "client_secret": "..."} out of band so
    the values never enter Terraform state. A Flight Control parent is one credential
    shared by all of its child tenants.
  EOT
  type = map(object({
    description = optional(string, "")
  }))
}

variable "tenants" {
  description = <<-EOT
    CrowdStrike tenants (CIDs) the server can reach, keyed by tenant id.
    base_url:      us1 | us2 | us3 | eu1 | usgov1 | usgov2, or an https://api…crowdstrike.com URL.
    credential:    key in falcon_credentials.
    member_cid:    set for a Flight Control child; credential must be the parent's.
    allow_actions: permit containment/alert updates for this tenant (still needs the responder role).
  EOT
  type = map(object({
    display_name  = string
    base_url      = string
    credential    = string
    member_cid    = optional(string)
    allow_actions = optional(bool, false)
    tags          = optional(list(string), [])
  }))

  validation {
    condition     = alltrue([for t in values(var.tenants) : contains(keys(var.falcon_credentials), t.credential)])
    error_message = "Every tenant.credential must be a key in falcon_credentials."
  }
  validation {
    condition     = alltrue([for id in keys(var.tenants) : can(regex("^[a-z0-9][a-z0-9-]{0,62}$", id))])
    error_message = "Tenant ids must be lowercase letters, digits and dashes."
  }
  validation {
    # FalconPy treats an unknown name as a hostname: a typo would send the API secret elsewhere.
    condition = alltrue([
      for t in values(var.tenants) : contains(["us1", "us2", "us3", "eu1", "usgov1", "usgov2"], replace(lower(t.base_url), "-", ""))
      || can(regex("^https://api(\\.[a-z0-9-]+)*\\.crowdstrike\\.(com|mil)/?$", lower(t.base_url)))
    ])
    error_message = "base_url must be us1, us2, us3, eu1, usgov1, usgov2 or an https://api…crowdstrike.com URL."
  }
  validation {
    condition = alltrue([
      for t in values(var.tenants) : t.member_cid == null || can(regex("^[0-9a-fA-F]{32}$", t.member_cid))
    ])
    error_message = "member_cid must be the 32 hex character CID, without the -XX checksum the console shows."
  }
  validation {
    condition = length(compact([for t in values(var.tenants) : t.member_cid == null ? "" : lower(t.member_cid)])) == length(distinct(compact([
      for t in values(var.tenants) : t.member_cid == null ? "" : lower(t.member_cid)
    ])))
    error_message = "Two tenants have the same member_cid."
  }
}

variable "access_grants" {
  description = <<-EOT
    Map IAM Identity Center groups (display names) to tenants and a role.
    tenants: list of tenant ids, or ["*"] for all. role: reader | responder.
    A user's role in a tenant is the highest role across all of their groups.
  EOT
  type = list(object({
    group   = string
    tenants = list(string)
    role    = string
  }))

  validation {
    condition     = alltrue([for g in var.access_grants : contains(["reader", "responder"], g.role)])
    error_message = "role must be reader or responder."
  }
  validation {
    condition = alltrue(flatten([
      for g in var.access_grants : [for t in g.tenants : t == "*" || contains(keys(var.tenants), t)]
    ]))
    error_message = "access_grants reference a tenant id that is not in var.tenants."
  }
  validation {
    condition = length(var.access_grants) == length(distinct([
      for g in var.access_grants : [g.group, g.role, sort(g.tenants)]
    ]))
    error_message = "access_grants contains the same grant twice."
  }
}

variable "actions_enabled" {
  description = "Global switch for write actions (containment, alert updates). Off by default."
  type        = bool
  default     = false
}

variable "max_action_targets" {
  description = "Maximum hosts or alerts a single action call may target."
  type        = number
  default     = 20
}

# --- IAM Identity Center -----------------------------------------------------------------

variable "identity_store_id" {
  description = "Identity Center identity store id (d-xxxxxxxxxx)."
  type        = string
}

variable "identity_store_region" {
  description = "Region Identity Center is enabled in. Defaults to aws_region."
  type        = string
  default     = null
}

variable "identity_store_role_arn" {
  description = <<-EOT
    Role to assume for Identity Store lookups when Identity Center lives in another account
    (management or delegated admin). Create it with modules/identity-center-reader.
    Leave null if Identity Center is in this account.
  EOT
  type        = string
  default     = null
}

variable "user_lookup_attribute" {
  description = "How the SAML NameID maps to an Identity Center user: userName or email."
  type        = string
  default     = "email"

  validation {
    condition     = contains(["userName", "email"], var.user_lookup_attribute)
    error_message = "user_lookup_attribute must be userName or email."
  }
}

variable "identity_center_saml_metadata_url" {
  description = <<-EOT
    SAML metadata URL of the customer managed application in Identity Center. Leave empty
    on the first apply, create the application from the outputs, then set this and apply again.
  EOT
  type        = string
  default     = ""
}

# --- OAuth / Cognito ---------------------------------------------------------------------

variable "cognito_domain_prefix" {
  description = "Globally unique prefix for the Cognito domain (<prefix>.auth.<region>.amazoncognito.com)."
  type        = string
}

variable "oauth_redirect_uris" {
  description = <<-EOT
    Redirect URIs MCP clients may use. Cognito matches them exactly, so fix the port on the
    client side (Claude Code: --callback-port 33418).
  EOT
  type        = list(string)
  default     = ["http://localhost:33418/callback"]
}

variable "access_token_minutes" {
  description = "Access token lifetime. Group changes still apply within 5 minutes; this bounds a leaked token."
  type        = number
  default     = 60

  validation {
    condition     = var.access_token_minutes >= 5 && var.access_token_minutes <= 1440
    error_message = "Cognito access tokens last 5 to 1440 minutes."
  }
}

variable "refresh_token_hours" {
  description = "How long a user stays signed in before re-authenticating through Identity Center."
  type        = number
  default     = 12

  validation {
    condition     = var.refresh_token_hours >= 1 && var.refresh_token_hours <= 87600
    error_message = "Cognito refresh tokens last 1 to 87600 hours."
  }
}

variable "public_base_url" {
  description = "Set when fronting the Function URL with a custom domain (CloudFront). Otherwise derived per request."
  type        = string
  default     = null
}

# --- Lambda ------------------------------------------------------------------------------

variable "lambda_zip_path" {
  description = "Package built by scripts/build_lambda.sh."
  type        = string
  default     = "../build/lambda.zip"
}

variable "lambda_memory_mb" {
  description = <<-EOT
    Lambda memory. CPU scales with it, and 1769 MB is one full vCPU; cold starts are CPU-bound
    (about 1s of imports), so they get faster with more memory. Requests are short and infrequent,
    so the cost difference is small.
  EOT
  type        = number
  default     = 1769
}

variable "lambda_timeout_seconds" {
  description = "Lambda timeout. Fan-out stops 10s earlier so partial results are still returned."
  type        = number
  default     = 60

  validation {
    condition     = var.lambda_timeout_seconds >= 20 && var.lambda_timeout_seconds <= 900
    error_message = "lambda_timeout_seconds must be between 20 and 900 (the fan-out deadline is 10s less)."
  }
}

variable "lambda_reserved_concurrency" {
  description = "Caps concurrent executions (and therefore Falcon API pressure). -1 for unreserved."
  type        = number
  default     = 20
}

variable "lambda_web_adapter_layer_version" {
  description = "Version of the public AWS Lambda Web Adapter layer (LambdaAdapterLayerArm64)."
  type        = number
  default     = 30
}

variable "log_retention_days" {
  description = "CloudWatch retention for the Lambda and audit logs."
  type        = number
  default     = 365
}

variable "kms_key_arn" {
  description = <<-EOT
    Optional customer managed KMS key for secrets, the config table, Lambda environment, logs and
    the alarm topic. Its key policy must allow logs.<region>.amazonaws.com (log group) and
    cloudwatch.amazonaws.com (alarms publishing to SNS), or those resources fail to create or deliver.
  EOT
  type        = string
  default     = null
}

# --- Alerting ------------------------------------------------------------------------------

variable "alarm_email" {
  description = "Email for audit alarms (denied calls, executed actions, Lambda errors). Null disables alarms."
  type        = string
  default     = null
}

variable "alarm_denied_threshold" {
  description = "Denied tool calls in 5 minutes that raise an alarm (probing or a misconfigured grant)."
  type        = number
  default     = 10
}

variable "alarm_on_actions" {
  description = "Alarm whenever a containment or alert-update action runs."
  type        = bool
  default     = true
}
