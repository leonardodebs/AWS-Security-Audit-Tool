"""
Central configuration for the AWS Security Audit Scanner.
All environment variables, defaults, and severity mappings live here.
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ScannerConfig:
    # AWS connection
    aws_region: str = field(default_factory=lambda: os.getenv("SCANNER_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1")))
    aws_profile: Optional[str] = field(default_factory=lambda: os.getenv("AWS_PROFILE"))
    aws_access_key_id: Optional[str] = field(default_factory=lambda: os.getenv("AWS_ACCESS_KEY_ID"))
    aws_secret_access_key: Optional[str] = field(default_factory=lambda: os.getenv("AWS_SECRET_ACCESS_KEY"))
    aws_session_token: Optional[str] = field(default_factory=lambda: os.getenv("AWS_SESSION_TOKEN"))

    # Output settings
    output_dir: str = field(default_factory=lambda: os.getenv("OUTPUT_DIR", "./reports"))
    report_formats: List[str] = field(default_factory=lambda: ["json", "html"])

    # Scan behaviour
    max_workers: int = field(default_factory=lambda: int(os.getenv("MAX_WORKERS", "5")))
    unused_key_days: int = field(default_factory=lambda: int(os.getenv("UNUSED_KEY_DAYS", "90")))

    # Lambda / CloudWatch (used by Terraform)
    lambda_schedule: str = field(default_factory=lambda: os.getenv("SCAN_SCHEDULE", "rate(24 hours)"))

    # S3 bucket for report upload (optional)
    report_s3_bucket: Optional[str] = field(default_factory=lambda: os.getenv("REPORT_S3_BUCKET"))


# Severity levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 4,
}

# Check IDs
CHECK_S3_PUBLIC_BUCKET = "S3-001"
CHECK_IAM_ADMIN_USER = "IAM-001"
CHECK_IAM_UNUSED_KEY = "IAM-002"
CHECK_EC2_OPEN_SG = "EC2-001"
CHECK_CT_ROOT_USAGE = "CT-001"
