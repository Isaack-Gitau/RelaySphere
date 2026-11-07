import pytest

from app.services.user_discovery import (
    InvalidCursorError,
    InvalidQueryError,
    decode_cursor,
    encode_cursor,
    escape_like,
    normalize_query,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("  Alice ", "alice"), ("AB", "ab"), ("a" * 80, "a" * 80), ("Ab Cd", "ab cd")],
)
def test_normalize_query_trims_and_lowercases(raw: str, expected: str) -> None:
    assert normalize_query(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", " ", "a", "a" * 81, "ab\x00", "a\x07b", "ab\x7f", "a\nb"],
)
def test_normalize_query_rejects_unusable_input(raw: str) -> None:
    with pytest.raises(InvalidQueryError):
        normalize_query(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("ab_", "ab!_"), ("100%", "100!%"), ("a!b", "a!!b"), ("plain", "plain")],
)
def test_escape_like_neutralizes_wildcards(raw: str, expected: str) -> None:
    assert escape_like(raw) == expected


def test_cursor_round_trips_without_padding() -> None:
    cursor = encode_cursor(1, "mira_njoroge")

    assert "=" not in cursor
    assert decode_cursor(cursor) == (1, "mira_njoroge")


@pytest.mark.parametrize("value", ["", "!!!", "a", "AAAA"])
def test_decode_cursor_rejects_malformed_values(value: str) -> None:
    with pytest.raises(InvalidCursorError):
        decode_cursor(value)
