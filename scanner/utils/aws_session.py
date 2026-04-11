"""
AWS session factory.
Supports static credentials, named profiles, and IAM role assumption.
"""

import logging
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from scanner.config import ScannerConfig

logger = logging.getLogger(__name__)


def get_session(config: ScannerConfig) -> boto3.Session:
    """
    Build and return a boto3 Session from the provided config.
    Priority: explicit keys > named profile > environment / instance profile.
    """
    try:
        if config.aws_access_key_id and config.aws_secret_access_key:
            logger.debug("Creating session from explicit credentials.")
            session = boto3.Session(
                aws_access_key_id=config.aws_access_key_id,
                aws_secret_access_key=config.aws_secret_access_key,
                aws_session_token=config.aws_session_token,
                region_name=config.aws_region,
            )
        elif config.aws_profile:
            logger.debug("Creating session from profile '%s'.", config.aws_profile)
            session = boto3.Session(
                profile_name=config.aws_profile,
                region_name=config.aws_region,
            )
        else:
            logger.debug("Creating session from default credential chain.")
            session = boto3.Session(region_name=config.aws_region)

        # Quick connectivity test
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        logger.info(
            "Authenticated as: %s (Account: %s)",
            identity.get("Arn"),
            identity.get("Account"),
        )
        return session

    except (BotoCoreError, ClientError) as exc:
        logger.error("Failed to create AWS session: %s", exc)
        raise


def get_client(session: boto3.Session, service: str, region: str | None = None):
    """Convenience wrapper to create a boto3 client."""
    return session.client(service, region_name=region)


def get_account_id(session: boto3.Session) -> str:
    """Return the AWS account ID for the active session."""
    sts = session.client("sts")
    return sts.get_caller_identity()["Account"]
