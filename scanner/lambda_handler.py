"""
AWS Lambda handler for scheduled security scans.

Triggered by EventBridge (CloudWatch Events) on a schedule defined in Terraform.
Results are stored as JSON in S3 and optionally published to SNS.
"""

from __future__ import annotations

import json
import logging
import os
import traceback
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event: dict, context) -> dict:
    """
    Lambda entry point.

    Environment variables (set by Terraform):
        REPORT_S3_BUCKET   – S3 bucket for storing scan reports
        AWS_DEFAULT_REGION – AWS region
        UNUSED_KEY_DAYS    – Threshold for unused key check (optional, default 90)
        SNS_TOPIC_ARN      – Optional SNS topic for alerts
    """
    logger.info("Lambda invoked. Event: %s", json.dumps(event))
    start = datetime.now(timezone.utc)

    try:
        # Import here to keep Lambda cold-start fast when testing
        from scanner.config import ScannerConfig
        from scanner.scanner import run_scan
        from reporting.json_reporter import JSONReporter
        from reporting.html_reporter import HTMLReporter

        config = ScannerConfig(
            aws_region=os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
            output_dir="/tmp/reports",
            report_s3_bucket=os.getenv("REPORT_S3_BUCKET"),
            unused_key_days=int(os.getenv("UNUSED_KEY_DAYS", "90")),
        )

        result = run_scan(config)

        # Generate and upload reports
        json_reporter = JSONReporter(
            output_dir="/tmp/reports",
            s3_bucket=config.report_s3_bucket,
        )
        html_reporter = HTMLReporter(
            output_dir="/tmp/reports",
            s3_bucket=config.report_s3_bucket,
        )
        json_path = json_reporter.generate(result)
        html_path = html_reporter.generate(result)

        # Publish summary to SNS if configured
        sns_arn = os.getenv("SNS_TOPIC_ARN")
        if sns_arn:
            _publish_sns(sns_arn, result)

        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        summary = result.get("summary", {})

        response = {
            "statusCode": 200,
            "body": {
                "message": "Scan complete",
                "account_id": result.get("account_id"),
                "scan_time": result.get("scan_time"),
                "elapsed_seconds": elapsed,
                "summary": summary,
                "json_report": json_path,
                "html_report": html_path,
            },
        }
        logger.info("Scan complete: %s", json.dumps(response["body"]))
        return response

    except Exception as exc:  # noqa: BLE001
        logger.error("Scan failed: %s\n%s", exc, traceback.format_exc())
        return {
            "statusCode": 500,
            "body": {"error": str(exc), "trace": traceback.format_exc()},
        }


def _publish_sns(topic_arn: str, result: dict):
    """Send a scan summary notification to an SNS topic."""
    try:
        import boto3
        sns = boto3.client("sns")
        summary = result.get("summary", {})
        by_sev = summary.get("by_severity", {})
        message = (
            f"AWS Security Audit Scan Complete\n"
            f"Account:  {result.get('account_id')}\n"
            f"Time:     {result.get('scan_time')}\n"
            f"Findings: {summary.get('total', 0)} total "
            f"({by_sev.get('CRITICAL', 0)} CRITICAL, "
            f"{by_sev.get('HIGH', 0)} HIGH, "
            f"{by_sev.get('MEDIUM', 0)} MEDIUM)\n"
        )
        sns.publish(
            TopicArn=topic_arn,
            Message=message,
            Subject="[AWS Security Audit] Scan Results",
        )
        logger.info("SNS notification published to %s", topic_arn)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to publish SNS notification: %s", exc)
