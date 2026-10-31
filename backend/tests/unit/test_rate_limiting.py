from datetime import UTC, datetime

import pytest

from app.services.rate_limiting import (
    RateLimitBucket,
    _window_start,
    consume_rate_limit_buckets,
)


@pytest.mark.parametrize(
    ("timestamp", "window_seconds", "expected"),
    [
        (
            datetime(2026, 1, 1, 12, 7, 30, tzinfo=UTC),
            900,
            datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
        ),
        (
            datetime(2026, 1, 1, 12, 59, 59, tzinfo=UTC),
            3600,
            datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
        ),
        (
            datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
            3600,
            datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
        ),
    ],
)
def test_window_start_aligns_to_fixed_epoch_windows(
    timestamp: datetime,
    window_seconds: int,
    expected: datetime,
) -> None:
    assert _window_start(timestamp, window_seconds) == expected


@pytest.mark.parametrize(
    ("timestamp", "window_seconds"),
    [
        (datetime(2026, 1, 1, 12, 0), 900),
        (datetime(2026, 1, 1, 12, 0, tzinfo=UTC), 0),
        (datetime(2026, 1, 1, 12, 0, tzinfo=UTC), -1),
    ],
)
def test_window_start_rejects_invalid_arguments(
    timestamp: datetime,
    window_seconds: int,
) -> None:
    with pytest.raises(ValueError):
        _window_start(timestamp, window_seconds)


@pytest.mark.parametrize(
    "bucket",
    [
        RateLimitBucket("", "ip", "192.0.2.1", 5, 900),
        RateLimitBucket("x" * 65, "ip", "192.0.2.1", 5, 900),
        RateLimitBucket("login", "ip", "192.0.2.1", 0, 900),
        RateLimitBucket("login", "ip", "192.0.2.1", 5, 0),
        RateLimitBucket("login", "ip", "192.0.2.1", 5, -1),
    ],
)
def test_consume_rejects_invalid_bucket_before_database_access(
    bucket: RateLimitBucket,
) -> None:
    def unexpected_session_factory():
        raise AssertionError("Database session should not be requested.")

    with pytest.raises(ValueError):
        consume_rate_limit_buckets(
            [bucket],
            session_factory=unexpected_session_factory,  # type: ignore[arg-type]
        )


def test_consume_rejects_empty_bucket_list() -> None:
    with pytest.raises(ValueError, match="At least one"):
        consume_rate_limit_buckets([])
