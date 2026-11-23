"""Canonical UTC timestamp helpers."""

from datetime import UTC, datetime

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode

_CANONICAL_LENGTH = len("2000-01-01T00:00:00Z")


def utc_now() -> datetime:
    """Return the current timezone-aware UTC instant at second precision."""
    return datetime.now(UTC).replace(microsecond=0)


def require_utc(value: datetime) -> datetime:
    """Normalize an aware datetime to UTC and remove sub-second precision."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise DomainError(
            DomainErrorCode.INVALID_TIMESTAMP,
            "timestamp must be timezone-aware",
        )
    return value.astimezone(UTC).replace(microsecond=0)


def format_utc(value: datetime) -> str:
    """Serialize an aware datetime as canonical second-precision RFC 3339."""
    return require_utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value: str) -> datetime:
    """Parse only the canonical persisted UTC representation."""
    if len(value) != _CANONICAL_LENGTH or not value.endswith("Z"):
        raise DomainError(
            DomainErrorCode.INVALID_TIMESTAMP,
            "timestamp must use YYYY-MM-DDTHH:MM:SSZ format",
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise DomainError(
            DomainErrorCode.INVALID_TIMESTAMP,
            "timestamp must use YYYY-MM-DDTHH:MM:SSZ format",
        ) from exc
    return parsed
