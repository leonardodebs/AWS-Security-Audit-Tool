"""
CT-001 – Detect root account usage via CloudTrail event history.

Looks for ConsoleLogin or any API event where the principal is the root account
within the last 90 days.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import List

from botocore.exceptions import ClientError

from scanner.checks.base import BaseCheck, Finding
from scanner.config import (
    CHECK_CT_ROOT_USAGE,
    SEVERITY_CRITICAL,
)

logger = logging.getLogger("aws_security_audit.CT-001")

_LOOKBACK_DAYS = 90


class CloudTrailRootUsageCheck(BaseCheck):
    check_id = CHECK_CT_ROOT_USAGE
    check_name = "Root Account Usage Detected"
    service = "cloudtrail"

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        ct = self._client("cloudtrail")
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=_LOOKBACK_DAYS)

        try:
            paginator = ct.get_paginator("lookup_events")
            for page in paginator.paginate(
                LookupAttributes=[
                    {"AttributeKey": "Username", "AttributeValue": "root"}
                ],
                StartTime=start_time,
                EndTime=end_time,
            ):
                for event in page.get("Events", []):
                    event_name = event.get("EventName", "Unknown")
                    event_time = event.get("EventTime", end_time)
                    event_id = event.get("EventId", "N/A")
                    source_ip = "N/A"
                    user_agent = "N/A"

                    # Extract CloudTrail record detail
                    ct_record = event.get("CloudTrailEvent")
                    if ct_record:
                        import json
                        try:
                            detail = json.loads(ct_record)
                            source_ip = detail.get("sourceIPAddress", "N/A")
                            user_agent = detail.get("userAgent", "N/A")
                        except (json.JSONDecodeError, TypeError):
                            pass

                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            check_name=self.check_name,
                            severity=SEVERITY_CRITICAL,
                            status="FAILED",
                            resource_type="AWS::CloudTrail::Event",
                            resource_id=event_id,
                            region=self.config.aws_region,
                            account_id=self.account_id,
                            description=(
                                f"Root account was used to perform '{event_name}' "
                                f"from IP {source_ip} at {event_time.isoformat() if hasattr(event_time, 'isoformat') else event_time}."
                            ),
                            recommendation=(
                                "The root account should never be used for day-to-day operations. "
                                "Enable MFA on the root account immediately. "
                                "Create least-privilege IAM users/roles. "
                                "Set up a CloudWatch alarm on root account usage."
                            ),
                            details={
                                "event_name": event_name,
                                "event_id": event_id,
                                "event_time": event_time.isoformat() if hasattr(event_time, "isoformat") else str(event_time),
                                "source_ip": source_ip,
                                "user_agent": user_agent,
                            },
                        )
                    )
        except ClientError as exc:
            logger.error("Cannot query CloudTrail events: %s", exc)

        if not findings:
            logger.info("CT-001: No root account usage detected in the last %d days.", _LOOKBACK_DAYS)

        return findings
