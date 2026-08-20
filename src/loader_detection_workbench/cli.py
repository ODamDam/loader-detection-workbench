"""Minimal command-line entry point for the M0 development bootstrap."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from importlib.metadata import version
from pathlib import Path

from loader_detection_workbench.config import (
    ConfigError,
    ConfigValueError,
    load_config,
    normalize_log_level,
)
from loader_detection_workbench.logging_config import configure_console_logging

_DISTRIBUTION_NAME = "loader-detection-workbench"


def _log_level_argument(value: str) -> str:
    try:
        return normalize_log_level(value)
    except ConfigValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    """Build the M0 global-options-only argument parser."""
    parser = argparse.ArgumentParser(
        prog="workbench",
        description="Local Detection-as-Code Workbench",
    )
    parser.add_argument(
        "--config",
        type=Path,
        metavar="FILE",
        help="load optional configuration from FILE",
    )
    parser.add_argument(
        "--log-level",
        type=_log_level_argument,
        metavar="LEVEL",
        help="set console logging level (default: INFO)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {version(_DISTRIBUTION_NAME)}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the minimal workbench CLI."""
    parser = build_parser()
    arguments = parser.parse_args(argv)

    try:
        config = load_config(arguments.config)
    except ConfigError as exc:
        parser.error(str(exc))

    log_level = arguments.log_level or config.log_level
    configure_console_logging(log_level)
    return 0
