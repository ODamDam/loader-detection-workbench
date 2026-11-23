from datetime import UTC, datetime, timedelta, timezone

import pytest

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import (
    format_utc,
    parse_utc,
    require_utc,
    utc_now,
)


def test_utc_now_is_aware_utc_at_second_precision() -> None:
    value = utc_now()

    assert value.tzinfo is UTC
    assert value.microsecond == 0


def test_naive_datetime_is_rejected() -> None:
    with pytest.raises(DomainError) as error:
        require_utc(datetime(2026, 9, 3, 12))

    assert error.value.code is DomainErrorCode.INVALID_TIMESTAMP


def test_aware_offset_is_normalized_preserving_instant() -> None:
    value = datetime(
        2026, 9, 3, 21, 30, 45, 987654, tzinfo=timezone(timedelta(hours=9))
    )

    assert require_utc(value) == datetime(2026, 9, 3, 12, 30, 45, tzinfo=UTC)


def test_canonical_timestamp_round_trip() -> None:
    serialized = "2026-09-03T12:30:45Z"

    assert format_utc(parse_utc(serialized)) == serialized


@pytest.mark.parametrize(
    "value",
    [
        "2026-09-03T12:30:45+00:00",
        "2026-09-03T12:30:45.123Z",
        "2026-09-03 12:30:45Z",
        "2026-02-30T12:30:45Z",
    ],
)
def test_noncanonical_timestamp_is_rejected(value: str) -> None:
    with pytest.raises(DomainError) as error:
        parse_utc(value)

    assert error.value.code is DomainErrorCode.INVALID_TIMESTAMP
