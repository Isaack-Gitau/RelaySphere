from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.schemas.auth import LoginRequest
from app.services.login import (
    InvalidCredentialsError,
    authenticate_user,
    get_access_token_expiry_seconds,
)

_UNSET = object()


def make_user(
    *,
    password_hash: str | None = "stored-hash",
    is_active: bool = True,
    email_verified_at: datetime | None | object = _UNSET,
) -> SimpleNamespace:
    """Build a user-like object for login service tests."""
    if email_verified_at is _UNSET:
        email_verified_at = datetime.now(UTC)

    return SimpleNamespace(
        id="test-user-id",
        email="isaack@example.com",
        password_hash=password_hash,
        is_active=is_active,
        email_verified_at=email_verified_at,
    )


def make_request() -> LoginRequest:
    """Build a valid login request."""
    return LoginRequest(
        email="Isaack@example.com",
        password="Correct-Horse-Battery-42!",
    )


def test_authenticate_user_returns_user_for_valid_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import login

    user = make_user()
    session = MagicMock()
    session.scalar.return_value = user

    monkeypatch.setattr(login, "verify_password", lambda password, stored_hash: True)

    result = authenticate_user(session, make_request())

    assert result is user
    session.scalar.assert_called_once()


@pytest.mark.parametrize(
    "user",
    [
        None,
        make_user(password_hash=None),
        make_user(is_active=False),
        make_user(email_verified_at=None),
    ],
    ids=[
        "unknown-user",
        "missing-password-hash",
        "inactive-user",
        "unverified-user",
    ],
)
def test_authenticate_user_rejects_unavailable_accounts(
    monkeypatch: pytest.MonkeyPatch,
    user: SimpleNamespace | None,
) -> None:
    from app.services import login

    session = MagicMock()
    session.scalar.return_value = user

    monkeypatch.setattr(login, "verify_password", lambda password, stored_hash: True)

    with pytest.raises(InvalidCredentialsError, match="Invalid email or password"):
        authenticate_user(session, make_request())


def test_authenticate_user_rejects_incorrect_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import login

    session = MagicMock()
    session.scalar.return_value = make_user()

    monkeypatch.setattr(login, "verify_password", lambda password, stored_hash: False)

    with pytest.raises(InvalidCredentialsError, match="Invalid email or password"):
        authenticate_user(session, make_request())


def test_authenticate_user_rejects_inactive_user_without_issuing_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import login

    session = MagicMock()
    session.scalar.return_value = make_user(is_active=False)

    monkeypatch.setattr(login, "verify_password", lambda password, stored_hash: True)

    with pytest.raises(InvalidCredentialsError):
        authenticate_user(session, make_request())


def test_access_token_expiry_uses_configured_lifetime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import login

    settings = SimpleNamespace(access_token_expire_minutes=15)
    monkeypatch.setattr(login, "get_settings", lambda: settings)

    assert get_access_token_expiry_seconds() == 900
