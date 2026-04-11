"""
Main scanner orchestrator.

Loads all check modules, runs them concurrently, aggregates findings,
and passes results to the reporting layer.
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Type

import boto3

from scanner.checks.base import BaseCheck, Finding
from scanner.checks.s3_public_buckets import S3PublicBucketCheck
from scanner.checks.iam_checks import IAMAdminUserCheck, IAMUnusedAccessKeyCheck
from scanner.checks.ec2_security_groups import EC2OpenSecurityGroupCheck
from scanner.checks.cloudtrail_root_usage import CloudTrailRootUsageCheck
from scanner.config import ScannerConfig, SEVERITY_ORDER
from scanner.utils.aws_session import get_session, get_account_id
from scanner.utils.logger import setup_logger

ALL_CHECKS: List[Type[BaseCheck]] = [
    S3PublicBucketCheck,
    IAMAdminUserCheck,
    IAMUnusedAccessKeyCheck,
    EC2OpenSecurityGroupCheck,
    CloudTrailRootUsageCheck,
]


def run_scan(config: ScannerConfig | None = None) -> dict:
    """
    Execute all checks and return a structured result dictionary.

    Args:
        config: ScannerConfig instance. Defaults to a fresh config from env vars.

    Returns:
        dict with keys: account_id, scan_time, summary, findings
    """
    if config is None:
        config = ScannerConfig()

    log_level = os.getenv("LOG_LEVEL", "INFO")
    logger = setup_logger(log_level=log_level)

    logger.info("=== AWS Security Audit Scanner starting ===")
    session = get_session(config)
    account_id = get_account_id(session)
    scan_time = datetime.now(timezone.utc).isoformat()

    all_findings: List[Finding] = []

    logger.info("Running %d security checks with %d workers.", len(ALL_CHECKS), config.max_workers)

    def _run_check(check_cls: Type[BaseCheck]) -> List[Finding]:
        check = check_cls(session=session, config=config, account_id=account_id)
        logger.info("Running check: %s [%s]", check.check_name, check.check_id)
        try:
            results = check.run()
            logger.info(
                "Check %s completed – %d finding(s).", check.check_id, len(results)
            )
            return results
        except Exception as exc:  # noqa: BLE001
            logger.error("Check %s raised an exception: %s", check.check_id, exc, exc_info=True)
            return []

    with ThreadPoolExecutor(max_workers=config.max_workers) as pool:
        futures = {pool.submit(_run_check, cls): cls for cls in ALL_CHECKS}
        for future in as_completed(futures):
            all_findings.extend(future.result())

    # Sort by severity then timestamp
    all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.timestamp))

    # Build summary
    summary = _build_summary(all_findings)

    logger.info(
        "=== Scan complete | Total findings: %d | CRITICAL: %d | HIGH: %d ===",
        summary["total"],
        summary["by_severity"].get("CRITICAL", 0),
        summary["by_severity"].get("HIGH", 0),
    )

    return {
        "account_id": account_id,
        "scan_time": scan_time,
        "summary": summary,
        "findings": [f.to_dict() for f in all_findings],
    }


def _build_summary(findings: List[Finding]) -> dict:
    by_severity: dict[str, int] = {}
    by_check: dict[str, int] = {}
    failed = 0

    for f in findings:
        if f.status == "FAILED":
            failed += 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_check[f.check_id] = by_check.get(f.check_id, 0) + 1

    return {
        "total": len(findings),
        "failed": failed,
        "by_severity": by_severity,
        "by_check": by_check,
    }
