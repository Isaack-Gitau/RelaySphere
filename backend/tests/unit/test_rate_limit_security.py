from types import SimpleNamespace

import pytest

from app.security import rate_limit


@pytest.fixture
def rate_limit_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        rate_limit,
        "get_settings",
        lambda: SimpleNamespace(
            rate_limit_secret="unit-test-rate-limit-secret-at-least-32-characters"
        ),
    )


def test_hash_identifier_returns_sha256_hex_digest(
    rate_limit_settings: None,
) -> None:
    result = rate_limit.hash_rate_limit_identifier("ip", "192.0.2.10")

    assert len(result) == 64
    assert all(character in "0123456789abcdef" for character in result)


def test_same_identifier_produces_same_hash(
    rate_limit_settings: None,
) -> None:
    first = rate_limit.hash_rate_limit_identifier("email", "user@example.test")
    second = rate_limit.hash_rate_limit_identifier("email", "user@example.test")

    assert first == second


def test_different_identifier_kinds_produce_different_hashes(
    rate_limit_settings: None,
) -> None:
    ip_hash = rate_limit.hash_rate_limit_identifier("ip", "user@example.test")
    email_hash = rate_limit.hash_rate_limit_identifier("email", "user@example.test")

    assert ip_hash != email_hash


def test_different_identifiers_produce_different_hashes(
    rate_limit_settings: None,
) -> None:
    first = rate_limit.hash_rate_limit_identifier("ip", "192.0.2.10")
    second = rate_limit.hash_rate_limit_identifier("ip", "192.0.2.11")

    assert first != second


def test_hash_changes_when_secret_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        rate_limit,
        "get_settings",
        lambda: SimpleNamespace(rate_limit_secret="first-test-secret-at-least-32-characters"),
    )
    first = rate_limit.hash_rate_limit_identifier("ip", "192.0.2.10")

    monkeypatch.setattr(
        rate_limit,
        "get_settings",
        lambda: SimpleNamespace(rate_limit_secret="second-test-secret-at-least-32-characters"),
    )
    second = rate_limit.hash_rate_limit_identifier("ip", "192.0.2.10")

    assert first != second


@pytest.mark.parametrize(
    "kind,value",
    [
        ("unknown", "value"),
        ("ip", ""),
        ("email", " "),
        ("ip", "x" * 513),
    ],
)
def test_hash_rejects_invalid_identifiers(
    rate_limit_settings: None,
    kind: str,
    value: str,
) -> None:
    with pytest.raises(ValueError):
        rate_limit.hash_rate_limit_identifier(kind, value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "secret",
    [None, "", "too-short", " " * 32],
)
def test_secret_validation_rejects_invalid_values(
    secret: str | None,
) -> None:
    with pytest.raises(RuntimeError, match="RATE_LIMIT_SECRET"):
        rate_limit.validate_rate_limit_secret(secret)


def test_secret_validation_accepts_sufficient_secret() -> None:
    rate_limit.validate_rate_limit_secret("unit-test-rate-limit-secret-at-least-32-characters")


def test_hashing_fails_closed_without_valid_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        rate_limit,
        "get_settings",
        lambda: SimpleNamespace(rate_limit_secret="too-short"),
    )

    with pytest.raises(RuntimeError, match="RATE_LIMIT_SECRET"):
        rate_limit.hash_rate_limit_identifier("ip", "192.0.2.10")
