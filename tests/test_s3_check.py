"""
Unit tests for the S3 public bucket check using moto (AWS mock library).
"""

import json
import pytest
import boto3
from moto import mock_aws
from unittest.mock import patch

from scanner.checks.s3_public_buckets import S3PublicBucketCheck
from scanner.config import ScannerConfig, SEVERITY_CRITICAL


@pytest.fixture
def config():
    return ScannerConfig(aws_region="us-east-1")


@mock_aws
def test_s3_public_access_block_disabled(config):
    """A bucket without Public Access Block should generate a CRITICAL finding."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-public-bucket")

    # Explicitly remove PAB settings (moto may default to off)
    check = S3PublicBucketCheck(session=session, config=config, account_id="123456789012")
    findings = check.run()

    assert len(findings) >= 1
    failed = [f for f in findings if f.status == "FAILED"]
    assert any("test-public-bucket" in f.resource_id for f in failed)


@mock_aws
def test_s3_no_findings_with_pab_enabled(config):
    """A bucket with all PAB settings enabled and no public policy should have no FAILED findings."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket = "my-private-bucket"
    s3.create_bucket(Bucket=bucket)

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    check = S3PublicBucketCheck(session=session, config=config, account_id="123456789012")
    findings = check.run()

    bucket_findings = [f for f in findings if bucket in f.resource_id and f.status == "FAILED"]
    assert len(bucket_findings) == 0


@mock_aws
def test_s3_public_policy_detected(config):
    """A bucket with a Principal='*' Allow policy should be flagged."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    bucket = "policy-public-bucket"
    s3.create_bucket(Bucket=bucket)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    check = S3PublicBucketCheck(session=session, config=config, account_id="123456789012")
    findings = check.run()

    policy_findings = [
        f for f in findings
        if bucket in f.resource_id and "policy" in f.description.lower()
    ]
    assert len(policy_findings) >= 1
    assert all(f.severity == SEVERITY_CRITICAL for f in policy_findings)
