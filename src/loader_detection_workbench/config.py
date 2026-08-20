"""Load the minimal optional M0 workbench configuration."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_LOG_LEVEL = "INFO"
SUPPORTED_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
_LOG_LEVEL_ALIASES = {"WARN": "WARNING"}


class ConfigError(Exception):
    """Base class for safe, user-facing configuration errors."""


class ConfigFileNotFoundError(ConfigError):
    """The explicitly selected configuration file does not exist."""


class ConfigReadError(ConfigError):
    """The selected configuration file cannot be read."""


class ConfigSyntaxError(ConfigError):
    """The selected configuration file is not valid TOML."""


class ConfigValueError(ConfigError):
    """A supported configuration setting contains an invalid value."""


@dataclass(frozen=True, slots=True)
class WorkbenchConfig:
    """Configuration required by the M0 command-line bootstrap."""

    log_level: str = DEFAULT_LOG_LEVEL


def normalize_log_level(value: str) -> str:
    """Normalize and validate a supported console log level."""
    normalized = value.strip().upper()
    normalized = _LOG_LEVEL_ALIASES.get(normalized, normalized)
    if normalized not in SUPPORTED_LOG_LEVELS:
        choices = ", ".join(sorted(SUPPORTED_LOG_LEVELS))
        raise ConfigValueError(f"unsupported log level; choose one of: {choices}")
    return normalized


def load_config(path: Path | None) -> WorkbenchConfig:
    """Load optional TOML without exposing its path or contents in errors."""
    if path is None:
        return WorkbenchConfig()

    try:
        with path.open("rb") as config_file:
            document = tomllib.load(config_file)
    except FileNotFoundError as exc:
        raise ConfigFileNotFoundError("configuration file was not found") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigSyntaxError("configuration file contains invalid TOML") from exc
    except (OSError, UnicodeError) as exc:
        raise ConfigReadError("configuration file could not be read") from exc

    workbench = document.get("workbench", {})
    if not isinstance(workbench, dict):
        raise ConfigValueError("workbench configuration must be a TOML table")

    log_level = workbench.get("log_level", DEFAULT_LOG_LEVEL)
    if not isinstance(log_level, str):
        raise ConfigValueError("workbench.log_level must be a string")

    return WorkbenchConfig(log_level=normalize_log_level(log_level))
