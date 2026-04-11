"""
Base class for all security checks.
Each check returns a list of Finding objects.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3

from scanner.config import ScannerConfig

logger = logging.getLogger("aws_security_audit")


@dataclass
class Finding:
    """Represents a single security finding discovered during a scan."""

    check_id: str
    check_name: str
    severity: str                    # CRITICAL | HIGH | MEDIUM | LOW | INFO
    status: str                      # FAILED | PASSED | WARNING
    resource_type: str
    resource_id: str
    region: str
    account_id: str
    description: str
    recommendation: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "severity": self.severity,
            "status": self.status,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "region": self.region,
            "account_id": self.account_id,
            "description": self.description,
            "recommendation": self.recommendation,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class BaseCheck(abc.ABC):
    """Abstract base class that every security check must implement."""

    check_id: str = ""
    check_name: str = ""
    service: str = ""

    def __init__(self, session: boto3.Session, config: ScannerConfig, account_id: str):
        self.session = session
        self.config = config
        self.account_id = account_id
        self.logger = logging.getLogger(f"aws_security_audit.{self.check_id}")

    @abc.abstractmethod
    def run(self) -> List[Finding]:
        """Execute the check and return a list of Finding objects."""

    def _client(self, service: str, region: Optional[str] = None):
        return self.session.client(service, region_name=region or self.config.aws_region)

    def _paginate(self, client, method: str, result_key: str, **kwargs) -> List[Any]:
        """Generic paginator helper."""
        paginator = client.get_paginator(method)
        results: List[Any] = []
        for page in paginator.paginate(**kwargs):
            results.extend(page.get(result_key, []))
        return results
