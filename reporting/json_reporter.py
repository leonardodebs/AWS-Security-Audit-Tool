"""
JSON reporter – writes the scan result to a timestamped .json file.
Optionally uploads the file to an S3 bucket.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aws_security_audit.reporting")


class JSONReporter:
    def __init__(self, output_dir: str = "./reports", s3_bucket: Optional[str] = None):
        self.output_dir = Path(output_dir)
        self.s3_bucket = s3_bucket

    def generate(self, result: dict) -> str:
        """
        Write the scan result dict to a JSON file.

        Returns:
            Absolute path to the written file.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        account_id = result.get("account_id", "unknown")
        filename = f"aws_security_audit_{account_id}_{timestamp}.json"
        filepath = self.output_dir / filename

        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, default=str)

        logger.info("JSON report written to: %s", filepath)

        if self.s3_bucket:
            self._upload_to_s3(filepath, filename)

        return str(filepath)

    def _upload_to_s3(self, local_path: Path, s3_key: str):
        try:
            import boto3
            s3 = boto3.client("s3")
            s3.upload_file(
                str(local_path),
                self.s3_bucket,
                f"reports/{s3_key}",
                ExtraArgs={"ContentType": "application/json"},
            )
            logger.info("JSON report uploaded to s3://%s/reports/%s", self.s3_bucket, s3_key)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to upload JSON report to S3: %s", exc)
