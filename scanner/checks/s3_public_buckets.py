"""
S3-001 – Detect publicly accessible S3 buckets.

Checks:
  - Bucket ACL grants public READ/WRITE to AllUsers or AuthenticatedUsers.
  - Bucket policy allows s3:GetObject or s3:* with Principal="*".
  - Public Access Block settings are fully disabled.
"""

from __future__ import annotations

import json
import logging
from typing import List

from botocore.exceptions import ClientError

from scanner.checks.base import BaseCheck, Finding
from scanner.config import (
    CHECK_S3_PUBLIC_BUCKET,
    SEVERITY_CRITICAL,
    ScannerConfig,
)

logger = logging.getLogger("aws_security_audit.S3-001")

_PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


class S3PublicBucketCheck(BaseCheck):
    check_id = CHECK_S3_PUBLIC_BUCKET
    check_name = "S3 Bucket Public Access"
    service = "s3"

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        s3 = self._client("s3", region="us-east-1")  # S3 control plane is global

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except ClientError as exc:
            logger.error("Cannot list S3 buckets: %s", exc)
            return findings

        for bucket in buckets:
            name = bucket["Name"]

            # Determine bucket region for the finding record
            try:
                loc = s3.get_bucket_location(Bucket=name)
                region = loc.get("LocationConstraint") or "us-east-1"
            except ClientError:
                region = "unknown"

            bucket_findings = self._check_bucket(s3, name, region)
            findings.extend(bucket_findings)

        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        bucket_name: str,
        region: str,
        description: str,
        details: dict,
    ) -> Finding:
        return Finding(
            check_id=self.check_id,
            check_name=self.check_name,
            severity=SEVERITY_CRITICAL,
            status="FAILED",
            resource_type="AWS::S3::Bucket",
            resource_id=f"arn:aws:s3:::{bucket_name}",
            region=region,
            account_id=self.account_id,
            description=description,
            recommendation=(
                "Enable S3 Block Public Access at both the account and bucket level. "
                "Review and tighten bucket ACLs and resource-based policies. "
                "Use AWS Config rule s3-bucket-public-read-prohibited to detect drift."
            ),
            details=details,
        )

    def _check_bucket(self, s3, bucket_name: str, region: str) -> List[Finding]:
        bucket_findings: List[Finding] = []

        # 1. Check Public Access Block configuration
        try:
            pab = s3.get_public_access_block(Bucket=bucket_name)
            cfg = pab.get("PublicAccessBlockConfiguration", {})
            block_all = all([
                cfg.get("BlockPublicAcls", False),
                cfg.get("IgnorePublicAcls", False),
                cfg.get("BlockPublicPolicy", False),
                cfg.get("RestrictPublicBuckets", False),
            ])
        except ClientError as exc:
            # NoSuchPublicAccessBlockConfiguration means settings are off
            if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                block_all = False
                cfg = {}
            else:
                logger.warning("Cannot check PAB for '%s': %s", bucket_name, exc)
                block_all = True  # assume safe if we can't read
                cfg = {}

        if not block_all:
            bucket_findings.append(
                self._make_finding(
                    bucket_name,
                    region,
                    f"Bucket '{bucket_name}' does not have all Public Access Block settings enabled.",
                    {"public_access_block": cfg},
                )
            )

        # 2. Check ACL
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                permission = grant.get("Permission", "")
                if uri in _PUBLIC_GRANTEES:
                    bucket_findings.append(
                        self._make_finding(
                            bucket_name,
                            region,
                            f"Bucket '{bucket_name}' ACL grants {permission} to {uri}.",
                            {"acl_grantee": uri, "permission": permission},
                        )
                    )
        except ClientError as exc:
            logger.warning("Cannot read ACL for '%s': %s", bucket_name, exc)

        # 3. Check bucket policy for public principal
        try:
            policy_str = s3.get_bucket_policy(Bucket=bucket_name).get("Policy", "{}")
            policy = json.loads(policy_str)
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal", "")
                effect = stmt.get("Effect", "")
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if effect == "Allow" and (
                    principal == "*"
                    or (isinstance(principal, dict) and principal.get("AWS") == "*")
                ):
                    bucket_findings.append(
                        self._make_finding(
                            bucket_name,
                            region,
                            f"Bucket '{bucket_name}' policy allows actions {actions} to Principal '*'.",
                            {"policy_statement": stmt},
                        )
                    )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucketPolicy":
                logger.warning("Cannot read policy for '%s': %s", bucket_name, exc)

        return bucket_findings
