"""
IAM-001 – Detect IAM users with admin privileges.
IAM-002 – Detect IAM users with unused access keys (>90 days).

Admin privilege detection:
  - Direct policy attachment: AdministratorAccess / Action *.
  - Group membership where the group has admin policy.
  - Inline policies with Action * / Effect Allow.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import List

from botocore.exceptions import ClientError

from scanner.checks.base import BaseCheck, Finding
from scanner.config import (
    CHECK_IAM_ADMIN_USER,
    CHECK_IAM_UNUSED_KEY,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    ScannerConfig,
)

logger = logging.getLogger("aws_security_audit.IAM")

_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _is_admin_policy(policy_document: dict) -> bool:
    """Return True if the policy document grants Action=* with Effect=Allow."""
    for stmt in policy_document.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if "*" in actions:
            return True
    return False


class IAMAdminUserCheck(BaseCheck):
    check_id = CHECK_IAM_ADMIN_USER
    check_name = "IAM User With Admin Privileges"
    service = "iam"

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        iam = self._client("iam")

        try:
            users = self._paginate(iam, "list_users", "Users")
        except ClientError as exc:
            logger.error("Cannot list IAM users: %s", exc)
            return findings

        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]
            admin_reasons: List[str] = []

            # 1. Managed policies attached directly
            try:
                managed = self._paginate(
                    iam, "list_attached_user_policies", "AttachedPolicies",
                    UserName=username,
                )
                for p in managed:
                    if p["PolicyArn"] == _ADMIN_POLICY_ARN:
                        admin_reasons.append(f"Managed policy: {p['PolicyArn']}")
            except ClientError as exc:
                logger.warning("Cannot list policies for '%s': %s", username, exc)

            # 2. Inline policies
            try:
                inline_names = self._paginate(
                    iam, "list_user_policies", "PolicyNames",
                    UserName=username,
                )
                for policy_name in inline_names:
                    resp = iam.get_user_policy(UserName=username, PolicyName=policy_name)
                    doc = resp.get("PolicyDocument", {})
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    if _is_admin_policy(doc):
                        admin_reasons.append(f"Inline policy: {policy_name}")
            except ClientError as exc:
                logger.warning("Cannot read inline policies for '%s': %s", username, exc)

            # 3. Group membership
            try:
                groups = self._paginate(
                    iam, "list_groups_for_user", "Groups",
                    UserName=username,
                )
                for group in groups:
                    group_name = group["GroupName"]
                    # Managed policies on group
                    grp_managed = self._paginate(
                        iam, "list_attached_group_policies", "AttachedPolicies",
                        GroupName=group_name,
                    )
                    for p in grp_managed:
                        if p["PolicyArn"] == _ADMIN_POLICY_ARN:
                            admin_reasons.append(
                                f"Group '{group_name}' has managed policy: {p['PolicyArn']}"
                            )
                    # Inline policies on group
                    grp_inline = self._paginate(
                        iam, "list_group_policies", "PolicyNames",
                        GroupName=group_name,
                    )
                    for policy_name in grp_inline:
                        resp = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                        doc = resp.get("PolicyDocument", {})
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        if _is_admin_policy(doc):
                            admin_reasons.append(
                                f"Group '{group_name}' inline policy: {policy_name}"
                            )
            except ClientError as exc:
                logger.warning("Cannot check groups for '%s': %s", username, exc)

            if admin_reasons:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        check_name=self.check_name,
                        severity=SEVERITY_CRITICAL,
                        status="FAILED",
                        resource_type="AWS::IAM::User",
                        resource_id=user_arn,
                        region="global",
                        account_id=self.account_id,
                        description=(
                            f"IAM user '{username}' has administrative privileges "
                            f"via: {'; '.join(admin_reasons)}."
                        ),
                        recommendation=(
                            "Apply the principle of least privilege. Replace AdministratorAccess "
                            "with scoped policies. Use IAM roles instead of long-lived user "
                            "credentials. Enable IAM Access Analyzer to detect overly permissive policies."
                        ),
                        details={"reasons": admin_reasons, "user_arn": user_arn},
                    )
                )

        return findings


class IAMUnusedAccessKeyCheck(BaseCheck):
    check_id = CHECK_IAM_UNUSED_KEY
    check_name = "IAM Unused Access Keys"
    service = "iam"

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        iam = self._client("iam")
        threshold = timedelta(days=self.config.unused_key_days)
        now = datetime.now(timezone.utc)

        try:
            users = self._paginate(iam, "list_users", "Users")
        except ClientError as exc:
            logger.error("Cannot list IAM users: %s", exc)
            return findings

        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]

            try:
                keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            except ClientError as exc:
                logger.warning("Cannot list keys for '%s': %s", username, exc)
                continue

            for key in keys:
                key_id = key["AccessKeyId"]
                status = key["Status"]
                create_date = key["CreateDate"]

                try:
                    last_used_resp = iam.get_access_key_last_used(AccessKeyId=key_id)
                    last_used_date = last_used_resp["AccessKeyLastUsed"].get("LastUsedDate")
                except ClientError:
                    last_used_date = None

                # Check if key is active but never used, or not used within threshold
                if status == "Active":
                    if last_used_date is None:
                        age_days = (now - create_date).days
                        if age_days >= self.config.unused_key_days:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    check_name=self.check_name,
                                    severity=SEVERITY_HIGH,
                                    status="FAILED",
                                    resource_type="AWS::IAM::AccessKey",
                                    resource_id=f"{user_arn}/AccessKey/{key_id}",
                                    region="global",
                                    account_id=self.account_id,
                                    description=(
                                        f"Access key '{key_id}' for user '{username}' is active "
                                        f"but has NEVER been used. Created {age_days} days ago."
                                    ),
                                    recommendation=(
                                        f"Deactivate or delete access keys unused for more than "
                                        f"{self.config.unused_key_days} days. "
                                        "Rotate credentials regularly. Prefer IAM roles over "
                                        "static access keys."
                                    ),
                                    details={
                                        "key_id": key_id,
                                        "created": create_date.isoformat(),
                                        "last_used": "Never",
                                        "age_days": age_days,
                                    },
                                )
                            )
                    elif (now - last_used_date) > threshold:
                        idle_days = (now - last_used_date).days
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                check_name=self.check_name,
                                severity=SEVERITY_HIGH,
                                status="FAILED",
                                resource_type="AWS::IAM::AccessKey",
                                resource_id=f"{user_arn}/AccessKey/{key_id}",
                                region="global",
                                account_id=self.account_id,
                                description=(
                                    f"Access key '{key_id}' for user '{username}' has not been "
                                    f"used for {idle_days} days (threshold: {self.config.unused_key_days})."
                                ),
                                recommendation=(
                                    f"Deactivate or delete access keys unused for more than "
                                    f"{self.config.unused_key_days} days. "
                                    "Rotate credentials regularly. Prefer IAM roles over "
                                    "static access keys."
                                ),
                                details={
                                    "key_id": key_id,
                                    "created": create_date.isoformat(),
                                    "last_used": last_used_date.isoformat(),
                                    "idle_days": idle_days,
                                },
                            )
                        )

        return findings
