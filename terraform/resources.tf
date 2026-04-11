##############################################################################
# S3 Bucket – stores scan reports
##############################################################################

resource "aws_s3_bucket" "reports" {
  bucket        = "${var.project_name}-reports-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = local.common_tags
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    id     = "expire-old-reports"
    status = "Enabled"
    filter { prefix = "reports/" }
    expiration { days = 365 }
    noncurrent_version_expiration { noncurrent_days = 30 }
  }
}

##############################################################################
# IAM Role for Lambda
##############################################################################

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.project_name}-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.common_tags
}

# Managed policies
resource "aws_iam_role_policy_attachment" "basic_execution" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Custom policy – read-only access to audited services
data "aws_iam_policy_document" "audit_permissions" {
  statement {
    sid    = "S3ReadOnly"
    effect = "Allow"
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketAcl",
      "s3:GetBucketPolicy",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketLocation",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "IAMReadOnly"
    effect = "Allow"
    actions = [
      "iam:ListUsers",
      "iam:ListAttachedUserPolicies",
      "iam:ListUserPolicies",
      "iam:GetUserPolicy",
      "iam:ListGroupsForUser",
      "iam:ListAttachedGroupPolicies",
      "iam:ListGroupPolicies",
      "iam:GetGroupPolicy",
      "iam:ListAccessKeys",
      "iam:GetAccessKeyLastUsed",
      "iam:GetPolicyVersion",
      "iam:GetPolicy",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "EC2ReadOnly"
    effect = "Allow"
    actions = [
      "ec2:DescribeRegions",
      "ec2:DescribeSecurityGroups",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "CloudTrailReadOnly"
    effect = "Allow"
    actions = [
      "cloudtrail:LookupEvents",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "STSIdentity"
    effect = "Allow"
    actions = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }

  statement {
    sid    = "S3ReportUpload"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
    ]
    resources = ["${aws_s3_bucket.reports.arn}/reports/*"]
  }

  dynamic "statement" {
    for_each = var.enable_sns_alerts ? [1] : []
    content {
      sid     = "SNSPublish"
      effect  = "Allow"
      actions = ["sns:Publish"]
      resources = [aws_sns_topic.alerts[0].arn]
    }
  }
}

resource "aws_iam_policy" "audit_permissions" {
  name   = "${var.project_name}-audit-policy"
  policy = data.aws_iam_policy_document.audit_permissions.json
  tags   = local.common_tags
}

resource "aws_iam_role_policy_attachment" "audit_permissions" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.audit_permissions.arn
}

##############################################################################
# Lambda deployment package
##############################################################################

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.root}/../"
  excludes = [
    "terraform/**",
    "dashboard/**",
    ".git/**",
    "**/__pycache__/**",
    "*.pyc",
    "*.egg-info/**",
    "reports/**",
    ".env",
    ".venv/**",
    "venv/**",
    "node_modules/**",
  ]
  output_path = "${path.root}/lambda_package.zip"
}

##############################################################################
# Lambda Function
##############################################################################

resource "aws_lambda_function" "scanner" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  function_name    = "${var.project_name}-scanner"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "scanner.lambda_handler.handler"
  runtime          = "python3.12"
  timeout          = var.lambda_timeout_seconds
  memory_size      = var.lambda_memory_mb

  environment {
    variables = {
      REPORT_S3_BUCKET  = aws_s3_bucket.reports.bucket
      SCANNER_REGION   = var.aws_region
      UNUSED_KEY_DAYS   = tostring(var.unused_key_days)
      SNS_TOPIC_ARN     = var.enable_sns_alerts ? aws_sns_topic.alerts[0].arn : ""
      LOG_LEVEL         = "INFO"
    }
  }

  tags = local.common_tags
}

##############################################################################
# CloudWatch Log Group
##############################################################################

resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/lambda/${aws_lambda_function.scanner.function_name}"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

##############################################################################
# EventBridge (CloudWatch Events) Scheduler
##############################################################################

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.project_name}-schedule"
  description         = "Trigger the AWS Security Audit scanner on a schedule."
  schedule_expression = var.scan_schedule_expression
  tags                = local.common_tags
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "SecurityAuditLambda"
  arn       = aws_lambda_function.scanner.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

##############################################################################
# SNS Topic (optional)
##############################################################################

resource "aws_sns_topic" "alerts" {
  count = var.enable_sns_alerts ? 1 : 0
  name  = "${var.project_name}-alerts"
  tags  = local.common_tags
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.enable_sns_alerts && var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

##############################################################################
# CloudWatch Alarm – Lambda errors
##############################################################################

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.project_name}-lambda-errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert when the security audit Lambda function errors."
  dimensions = {
    FunctionName = aws_lambda_function.scanner.function_name
  }
  alarm_actions = var.enable_sns_alerts ? [aws_sns_topic.alerts[0].arn] : []
  tags          = local.common_tags
}

##############################################################################
# Locals
##############################################################################

locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}
