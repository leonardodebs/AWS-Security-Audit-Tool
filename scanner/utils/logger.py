"""
Logging configuration for the AWS Security Audit Scanner.
Outputs structured JSON-compatible logs to stdout; additionally writes to a
rotating file handler when running locally.
"""

import logging
import sys
import os
from logging.handlers import RotatingFileHandler


def setup_logger(
    name: str = "aws_security_audit",
    log_level: str = "INFO",
    log_file: str | None = None,
) -> logging.Logger:
    """
    Configure and return the root scanner logger.

    Args:
        name:      Logger name (used as a prefix in all log records).
        log_level: Minimum log level string (DEBUG, INFO, WARNING, ERROR).
        log_file:  Optional path for a rotating log file.

    Returns:
        Configured logging.Logger instance.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers on re-import
    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # Optional rotating file handler
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        fh = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
        fh.setLevel(level)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger
