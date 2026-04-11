##############################################################################
# AWS Security Audit – Terraform Root Module
# Provisions: Lambda, IAM role/policies, EventBridge schedule, S3 bucket,
#             CloudWatch log group, optional SNS topic.
##############################################################################

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}
