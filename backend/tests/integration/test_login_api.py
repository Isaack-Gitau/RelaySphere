from collections.abc import Generator
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.main import app
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.security.passwords import hash_password
from app.security.tokens import decode_access_token


@pytest.fixture
def api_client(
    db_session: Session,
) -> Generator[TestClient]:
    """Use the isolated integration-test session for HTTP requests."""

    def override_db_session() -> Generator[Session]:
        yield db_session

    app.dependency_overrides[get_db_session] = override_db_session

    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db_session, None)


def create_user(
    db_session: Session,
    *,
    email: str = "login@example.com",
    password: str = "Correct-Horse-Battery-42!",
    is_active: bool = True,
    verified: bool = True,
) -> User:
    """Create a user for an isolated login API test."""

    user = User(
        email=email,
        display_name="Login Test User",
        password_hash=hash_password(password),
        is_active=is_active,
        email_verified_at=datetime.now(UTC) if verified else None,
    )

    db_session.add(user)
    db_session.flush()

    return user


def test_login_returns_access_token_for_valid_credentials(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.security import tokens

    monkeypatch.setattr(
        tokens,
        "get_settings",
        lambda: SimpleNamespace(
            access_token_secret="integration-test-secret-at-least-32-characters",
            access_token_expire_minutes=15,
        ),
    )

    user = create_user(db_session)

    response = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": "LOGIN@example.com",
            "password": "Correct-Horse-Battery-42!",
        },
    )

    assert response.status_code == 200

    cookie = response.headers.get("set-cookie", "")
    assert "relaysphere_refresh=" in cookie
    assert "httponly" in cookie.lower()
    assert "samesite=lax" in cookie.lower()
    assert "path=/api/v1/auth" in cookie.lower()
    max_age = int(cookie.lower().split("max-age=", 1)[1].split(";", 1)[0])
    refresh_record = db_session.scalar(
        select(RefreshSession).where(RefreshSession.user_id == user.id)
    )
    assert refresh_record is not None
    expires_at = refresh_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    remaining_seconds = int((expires_at - datetime.now(UTC)).total_seconds())
    assert 0 < max_age <= remaining_seconds
    assert "secure" not in cookie.lower()

    data = response.json()
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 900
    assert isinstance(data["access_token"], str)
    assert data["access_token"]

    claims = decode_access_token(data["access_token"])
    assert claims["sub"] == str(user.id)
    assert claims["type"] == "access"

    assert "password" not in data
    assert "password_hash" not in data


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("login@example.com", "Wrong-Password-42!"),
        ("unknown@example.com", "Correct-Horse-Battery-42!"),
    ],
    ids=["incorrect-password", "unknown-email"],
)
def test_login_rejects_invalid_credentials(
    api_client: TestClient,
    db_session: Session,
    email: str,
    password: str,
) -> None:
    create_user(db_session)

    response = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password."}
    assert response.headers["www-authenticate"] == "Bearer"
    assert "access_token" not in response.json()


@pytest.mark.parametrize(
    ("is_active", "verified"),
    [
        (True, False),
        (False, True),
        (False, False),
    ],
    ids=[
        "unverified-account",
        "inactive-account",
        "inactive-and-unverified-account",
    ],
)
def test_login_rejects_unavailable_accounts(
    api_client: TestClient,
    db_session: Session,
    is_active: bool,
    verified: bool,
) -> None:
    create_user(
        db_session,
        is_active=is_active,
        verified=verified,
    )

    response = api_client.post(
        "/api/v1/auth/login",
        json={
            "email": "login@example.com",
            "password": "Correct-Horse-Battery-42!",
        },
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password."}
    assert response.headers["www-authenticate"] == "Bearer"
