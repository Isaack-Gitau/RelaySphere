from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import get_settings
from app.security.tokens import create_access_token, decode_access_token

SESSION_ID = "11111111-1111-4111-8111-111111111111"


@pytest.fixture
def token_secret(monkeypatch: pytest.MonkeyPatch) -> Generator[str]:
    secret = "test-only-secret-that-is-long-enough-for-hmac-sha256"
    monkeypatch.setenv("ACCESS_TOKEN_SECRET", secret)
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15")
    get_settings.cache_clear()

    yield secret

    get_settings.cache_clear()


def test_create_and_decode_access_token(token_secret: str) -> None:
    token = create_access_token(subject="user-123", session_id=SESSION_ID)
    claims = decode_access_token(token)

    assert claims["sub"] == "user-123"
    assert claims["sid"] == SESSION_ID
    assert claims["type"] == "access"
    assert isinstance(claims["iat"], int)
    assert isinstance(claims["exp"], int)
    assert claims["exp"] > claims["iat"]


def test_access_token_uses_hs256(token_secret: str) -> None:
    token = create_access_token(subject="user-123", session_id=SESSION_ID)

    assert jwt.get_unverified_header(token)["alg"] == "HS256"


def test_decode_rejects_tampered_token(token_secret: str) -> None:
    token = create_access_token(subject="user-123", session_id=SESSION_ID)
    parts = token.split(".")
    tampered = ".".join([parts[0], parts[1] + "x", parts[2]])

    with pytest.raises(ValueError):
        decode_access_token(tampered)


def test_decode_rejects_expired_token(token_secret: str) -> None:
    now = datetime.now(UTC)
    expired_token = jwt.encode(
        {
            "sub": "user-123",
            "sid": SESSION_ID,
            "type": "access",
            "iat": now - timedelta(minutes=20),
            "exp": now - timedelta(minutes=5),
        },
        token_secret,
        algorithm="HS256",
    )

    with pytest.raises(ValueError):
        decode_access_token(expired_token)


def test_decode_rejects_refresh_token_type(token_secret: str) -> None:
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "user-123",
            "sid": SESSION_ID,
            "type": "refresh",
            "iat": now,
            "exp": now + timedelta(minutes=15),
        },
        token_secret,
        algorithm="HS256",
    )

    with pytest.raises(ValueError, match="not an access token"):
        decode_access_token(token)


@pytest.mark.parametrize("missing_claim", ["sub", "sid", "type", "iat", "exp"])
def test_decode_rejects_missing_required_claim(
    token_secret: str,
    missing_claim: str,
) -> None:
    now = datetime.now(UTC)
    claims = {
        "sub": "user-123",
        "sid": SESSION_ID,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=15),
    }
    del claims[missing_claim]

    token = jwt.encode(
        claims,
        token_secret,
        algorithm="HS256",
    )

    with pytest.raises(ValueError):
        decode_access_token(token)


def test_decode_rejects_unexpected_signing_algorithm(
    token_secret: str,
) -> None:
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "user-123",
            "sid": SESSION_ID,
            "type": "access",
            "iat": now,
            "exp": now + timedelta(minutes=15),
        },
        token_secret,
        algorithm="HS384",
    )

    with pytest.raises(ValueError):
        decode_access_token(token)


def test_create_token_rejects_missing_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ACCESS_TOKEN_SECRET", raising=False)
    get_settings.cache_clear()

    try:
        with pytest.raises(RuntimeError):
            create_access_token(subject="user-123", session_id=SESSION_ID)
    finally:
        get_settings.cache_clear()


def test_create_token_rejects_short_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACCESS_TOKEN_SECRET", "too-short")
    get_settings.cache_clear()

    try:
        with pytest.raises(RuntimeError, match="at least 32 characters"):
            create_access_token(subject="user-123", session_id=SESSION_ID)
    finally:
        get_settings.cache_clear()


@pytest.mark.parametrize("subject", ["", " ", "\n"])
def test_create_token_rejects_blank_subject(
    token_secret: str,
    subject: str,
) -> None:
    with pytest.raises(ValueError):
        create_access_token(subject=subject, session_id=SESSION_ID)


@pytest.mark.parametrize("subject", [None, 123, []])
def test_create_token_rejects_non_string_subject(
    token_secret: str,
    subject: object,
) -> None:
    with pytest.raises(ValueError):
        create_access_token(subject=subject, session_id=SESSION_ID)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("claim", "invalid_value"),
    [
        ("sub", 123),
        ("iat", "not-a-timestamp"),
        ("exp", "not-a-timestamp"),
    ],
)
def test_decode_rejects_invalid_claim_types(
    token_secret: str,
    claim: str,
    invalid_value: object,
) -> None:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "sub": "user-123",
        "sid": SESSION_ID,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=15),
    }
    claims[claim] = invalid_value

    token = jwt.encode(
        claims,
        token_secret,
        algorithm="HS256",
    )

    with pytest.raises(ValueError):
        decode_access_token(token)
