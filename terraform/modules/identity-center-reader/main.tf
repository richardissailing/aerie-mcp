# Apply in the account that hosts IAM Identity Center (management or delegated admin)
# when the MCP Lambda runs in a different account.

terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "lambda_role_arn" {
  description = "lambda_role_arn output of the main stack."
  type        = string
}

variable "identity_store_id" {
  type = string
}

variable "role_name" {
  type    = string
  default = "falcon-fleet-mcp-identity-reader"
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_iam_role" "reader" {
  name = var.role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.lambda_role_arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "reader" {
  role = aws_iam_role.reader.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["identitystore:GetUserId", "identitystore:ListGroupMembershipsForMember", "identitystore:DescribeGroup"]
      Resource = [
        "arn:${data.aws_partition.current.partition}:identitystore::${data.aws_caller_identity.current.account_id}:identitystore/${var.identity_store_id}",
        "arn:${data.aws_partition.current.partition}:identitystore:::user/*",
        "arn:${data.aws_partition.current.partition}:identitystore:::group/*",
        "arn:${data.aws_partition.current.partition}:identitystore:::membership/*",
      ]
    }]
  })
}

output "role_arn" {
  description = "Set as identity_store_role_arn in the main stack."
  value       = aws_iam_role.reader.arn
}
