##############################################################################
# Variables
##############################################################################

variable "aws_region" {
  description = "AWS region to deploy resources into."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix applied to all resource names."
  type        = string
  default     = "aws-security-audit"
}

variable "environment" {
  description = "Environment tag (e.g. prod, staging)."
  type        = string
  default     = "prod"
}

variable "scan_schedule_expression" {
  description = "EventBridge schedule expression for the Lambda trigger."
  type        = string
  default     = "rate(24 hours)"
}

variable "unused_key_days" {
  description = "Number of days after which an access key is considered unused."
  type        = number
  default     = 90
}

variable "enable_sns_alerts" {
  description = "Whether to create an SNS topic and alert on scan completion."
  type        = bool
  default     = true
}

variable "alert_email" {
  description = "E-mail address to receive SNS scan-complete alerts. Required when enable_sns_alerts=true."
  type        = string
  default     = ""
}

variable "lambda_memory_mb" {
  description = "Lambda function memory in MB."
  type        = number
  default     = 512
}

variable "lambda_timeout_seconds" {
  description = "Lambda function timeout in seconds."
  type        = number
  default     = 900 # 15 minutes
}

variable "log_retention_days" {
  description = "CloudWatch log group retention in days."
  type        = number
  default     = 90
}
