from datetime import UTC, datetime, timedelta

from app.services.refresh_sessions import REAUTH_WINDOW, is_recently_reauthenticated

NOW = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)


def test_window_is_ten_minutes() -> None:
    assert REAUTH_WINDOW == timedelta(minutes=10)


def test_missing_marker_is_denied() -> None:
    assert is_recently_reauthenticated(None, NOW) is False


def test_just_inside_window_is_allowed() -> None:
    assert is_recently_reauthenticated(NOW - timedelta(minutes=9, seconds=59), NOW) is True


def test_marker_set_now_is_allowed() -> None:
    assert is_recently_reauthenticated(NOW, NOW) is True


def test_exactly_ten_minutes_is_denied() -> None:
    assert is_recently_reauthenticated(NOW - timedelta(minutes=10), NOW) is False


def test_older_than_window_is_denied() -> None:
    assert is_recently_reauthenticated(NOW - timedelta(minutes=10, seconds=1), NOW) is False


def test_future_marker_is_denied() -> None:
    assert is_recently_reauthenticated(NOW + timedelta(seconds=1), NOW) is False


def test_naive_marker_is_treated_as_utc() -> None:
    naive = (NOW - timedelta(minutes=5)).replace(tzinfo=None)
    assert is_recently_reauthenticated(naive, NOW) is True
