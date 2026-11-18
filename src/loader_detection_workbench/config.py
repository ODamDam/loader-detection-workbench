"""Load the minimal optional M0 workbench configuration."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
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


# External analysis providers (ADR-031). Model names are configurable because
# provider catalogues and prices change; the defaults are low-cost tiers.
AI_PROVIDERS = ("openai", "deepseek", "gemini")
DEFAULT_AI_MODELS = {
    "openai": "gpt-5-mini",
    "deepseek": "deepseek-flash",
    "gemini": "gemini-2.5-flash",
}
_MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}", re.ASCII)


@dataclass(frozen=True, slots=True)
class AiConfig:
    """``[ai]``: external calls stay off unless ``allow_network = true``."""

    allow_network: bool = False
    models: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_AI_MODELS))


@dataclass(frozen=True, slots=True)
class WorkbenchConfig:
    """Configuration required by the M0 command-line bootstrap."""

    log_level: str = DEFAULT_LOG_LEVEL
    ai: AiConfig = field(default_factory=AiConfig)


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

    return WorkbenchConfig(
        log_level=normalize_log_level(log_level), ai=_ai_config(document.get("ai", {}))
    )


def _ai_config(table: object) -> AiConfig:
    if not isinstance(table, dict):
        raise ConfigValueError("ai configuration must be a TOML table")
    unknown = set(table) - {"allow_network", "models"}
    if unknown:
        raise ConfigValueError("ai configuration has unsupported keys")
    allow = table.get("allow_network", False)
    if not isinstance(allow, bool):
        raise ConfigValueError("ai.allow_network must be true or false")
    models = dict(DEFAULT_AI_MODELS)
    given = table.get("models", {})
    if not isinstance(given, dict) or set(given) - set(AI_PROVIDERS):
        raise ConfigValueError("ai.models may only name openai, deepseek and gemini")
    for name, model in given.items():
        if not isinstance(model, str) or _MODEL_NAME.fullmatch(model) is None:
            raise ConfigValueError("ai.models values must be plain model names")
        models[name] = model
    return AiConfig(allow_network=allow, models=models)
