##############################################################################
# Outputs
##############################################################################

output "lambda_function_name" {
  description = "Name of the deployed Lambda scanner function."
  value       = aws_lambda_function.scanner.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda scanner function."
  value       = aws_lambda_function.scanner.arn
}

output "reports_bucket_name" {
  description = "S3 bucket name where scan reports are stored."
  value       = aws_s3_bucket.reports.bucket
}

output "reports_bucket_arn" {
  description = "S3 bucket ARN."
  value       = aws_s3_bucket.reports.arn
}

output "eventbridge_rule_name" {
  description = "EventBridge rule that triggers the scanner."
  value       = aws_cloudwatch_event_rule.schedule.name
}

output "scan_schedule" {
  description = "Configured scan schedule expression."
  value       = var.scan_schedule_expression
}

output "sns_topic_arn" {
  description = "SNS topic ARN for alerts (empty if disabled)."
  value       = var.enable_sns_alerts ? aws_sns_topic.alerts[0].arn : ""
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for the Lambda function."
  value       = aws_cloudwatch_log_group.scanner.name
}
