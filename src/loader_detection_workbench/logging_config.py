"""Console-only logging configuration for the workbench CLI."""

from __future__ import annotations

import logging
import sys

LOGGER_NAME = "loader_detection_workbench"


def configure_console_logging(level: str) -> logging.Logger:
    """Configure and return the package logger with one console handler."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger
