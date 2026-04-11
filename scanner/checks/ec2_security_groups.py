"""
EC2-001 – Detect security groups with unrestricted inbound access (0.0.0.0/0 or ::/0).

High-risk ports flagged as CRITICAL; any open port flagged as HIGH.
"""

from __future__ import annotations

import logging
from typing import List

from botocore.exceptions import ClientError

from scanner.checks.base import BaseCheck, Finding
from scanner.config import (
    CHECK_EC2_OPEN_SG,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    ScannerConfig,
)

logger = logging.getLogger("aws_security_audit.EC2-001")

# Ports considered critically dangerous when open to the world
_CRITICAL_PORTS = {
    22,    # SSH
    3389,  # RDP
    3306,  # MySQL
    5432,  # PostgreSQL
    27017, # MongoDB
    6379,  # Redis
    9200,  # Elasticsearch
    5601,  # Kibana
    2375,  # Docker daemon (unencrypted)
    2376,  # Docker daemon (TLS)
}

_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


class EC2OpenSecurityGroupCheck(BaseCheck):
    check_id = CHECK_EC2_OPEN_SG
    check_name = "EC2 Security Group Open to World"
    service = "ec2"

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        # Iterate over every enabled region
        ec2_global = self._client("ec2")
        try:
            regions_resp = ec2_global.describe_regions(
                Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
            )
            regions = [r["RegionName"] for r in regions_resp.get("Regions", [])]
        except ClientError as exc:
            logger.error("Cannot list EC2 regions: %s", exc)
            regions = [self.config.aws_region]

        for region in regions:
            findings.extend(self._scan_region(region))

        return findings

    def _scan_region(self, region: str) -> List[Finding]:
        findings: List[Finding] = []
        ec2 = self._client("ec2", region=region)

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    findings.extend(self._check_sg(sg, region))
        except ClientError as exc:
            logger.warning("Cannot list security groups in %s: %s", region, exc)

        return findings

    def _check_sg(self, sg: dict, region: str) -> List[Finding]:
        findings: List[Finding] = []
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)
        vpc_id = sg.get("VpcId", "N/A")

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)
            protocol = rule.get("IpProtocol", "all")

            open_cidrs_found = []
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") in _OPEN_CIDRS:
                    open_cidrs_found.append(ip_range["CidrIp"])
            for ip_range in rule.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") in _OPEN_CIDRS:
                    open_cidrs_found.append(ip_range["CidrIpv6"])

            if not open_cidrs_found:
                continue

            # Determine affected port range
            if protocol == "-1":
                port_desc = "ALL TRAFFIC"
                is_critical = True
            elif from_port == to_port:
                port_desc = str(from_port)
                is_critical = from_port in _CRITICAL_PORTS
            else:
                port_desc = f"{from_port}-{to_port}"
                is_critical = bool(_CRITICAL_PORTS & set(range(from_port, to_port + 1)))

            severity = SEVERITY_CRITICAL if is_critical else SEVERITY_HIGH

            findings.append(
                Finding(
                    check_id=self.check_id,
                    check_name=self.check_name,
                    severity=severity,
                    status="FAILED",
                    resource_type="AWS::EC2::SecurityGroup",
                    resource_id=sg_id,
                    region=region,
                    account_id=self.account_id,
                    description=(
                        f"Security group '{sg_name}' ({sg_id}) in VPC {vpc_id} allows "
                        f"inbound {protocol.upper()} port {port_desc} from {open_cidrs_found}."
                    ),
                    recommendation=(
                        "Restrict inbound rules to specific IP ranges or CIDR blocks. "
                        "Use AWS Systems Manager Session Manager instead of opening SSH/RDP. "
                        "Apply security group scoping and enable VPC Flow Logs."
                    ),
                    details={
                        "sg_id": sg_id,
                        "sg_name": sg_name,
                        "vpc_id": vpc_id,
                        "protocol": protocol,
                        "port_range": port_desc,
                        "open_cidrs": open_cidrs_found,
                    },
                )
            )

        return findings
