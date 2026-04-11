"""
CLI entry-point for the AWS Security Audit Scanner.

Usage:
    python -m scanner.main [OPTIONS]

Options:
    --region        AWS region (default: us-east-1)
    --profile       AWS named profile
    --format        Report format: json, html, or both (default: both)
    --output-dir    Directory for output reports (default: ./reports)
    --log-level     Logging verbosity (default: INFO)
    --unused-days   Days before an access key is considered unused (default: 90)
"""

from __future__ import annotations

import argparse
import sys
import os

from scanner.config import ScannerConfig
from scanner.scanner import run_scan
from scanner.utils.logger import setup_logger
from reporting.json_reporter import JSONReporter
from reporting.html_reporter import HTMLReporter


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aws-security-audit",
        description="Scan an AWS account and detect security risks.",
    )
    parser.add_argument("--region", default=os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
    parser.add_argument("--profile", default=os.getenv("AWS_PROFILE"))
    parser.add_argument(
        "--format",
        choices=["json", "html", "both"],
        default="both",
        help="Output format (default: both)",
    )
    parser.add_argument("--output-dir", default="./reports")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )
    parser.add_argument(
        "--unused-days",
        type=int,
        default=90,
        help="Days before an access key is flagged as unused.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logger(log_level=args.log_level)

    config = ScannerConfig(
        aws_region=args.region,
        aws_profile=args.profile,
        output_dir=args.output_dir,
        unused_key_days=args.unused_days,
    )

    result = run_scan(config)

    os.makedirs(args.output_dir, exist_ok=True)

    formats = ["json", "html"] if args.format == "both" else [args.format]

    for fmt in formats:
        if fmt == "json":
            reporter = JSONReporter(output_dir=args.output_dir)
        else:
            reporter = HTMLReporter(output_dir=args.output_dir)
        path = reporter.generate(result)
        print(f"[{fmt.upper()}] Report saved: {path}")

    critical = result["summary"]["by_severity"].get("CRITICAL", 0)
    high = result["summary"]["by_severity"].get("HIGH", 0)

    # Return non-zero exit code if critical/high findings exist
    if critical > 0 or high > 0:
        print(f"\n⚠  {critical} CRITICAL and {high} HIGH findings detected.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
