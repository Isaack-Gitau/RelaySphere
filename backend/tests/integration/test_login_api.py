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
        with TestClient(app, headers={"Origin": "http://localhost:5173"}) as client:
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
    from app.security import csrf, tokens

    monkeypatch.setattr(
        tokens,
        "get_settings",
        lambda: SimpleNamespace(
            access_token_secret="integration-test-secret-at-least-32-characters",
            access_token_expire_minutes=15,
        ),
    )

    monkeypatch.setattr(
        csrf,
        "get_settings",
        lambda: SimpleNamespace(
            csrf_secret="integration-test-csrf-secret-at-least-32-characters",
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

    set_cookie_headers = response.headers.get_list("set-cookie")
    refresh_cookie = next(
        cookie for cookie in set_cookie_headers if cookie.startswith("relaysphere_refresh=")
    )
    csrf_cookie_header = next(
        cookie for cookie in set_cookie_headers if cookie.startswith("relaysphere_csrf=")
    )

    refresh_cookie_lower = refresh_cookie.lower()
    csrf_cookie_lower = csrf_cookie_header.lower()

    assert "httponly" in refresh_cookie_lower
    assert "httponly" not in csrf_cookie_lower
    assert "samesite=lax" in refresh_cookie_lower
    assert "samesite=lax" in csrf_cookie_lower
    assert "path=/api/v1/auth" in refresh_cookie_lower
    assert "path=/api/v1/auth" in csrf_cookie_lower
    assert "secure" not in refresh_cookie_lower
    assert "secure" not in csrf_cookie_lower

    max_age = int(refresh_cookie_lower.split("max-age=", 1)[1].split(";", 1)[0])
    refresh_record = db_session.scalar(
        select(RefreshSession).where(RefreshSession.user_id == user.id)
    )
    assert refresh_record is not None
    expires_at = refresh_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    remaining_seconds = int((expires_at - datetime.now(UTC)).total_seconds())
    assert 0 < max_age <= remaining_seconds

    csrf_cookie = response.cookies.get("relaysphere_csrf")
    assert isinstance(csrf_cookie, str)
    assert csrf_cookie.startswith("v1.")

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

    reauthenticated_at = refresh_record.reauthenticated_at
    assert reauthenticated_at is not None
    if reauthenticated_at.tzinfo is None:
        reauthenticated_at = reauthenticated_at.replace(tzinfo=UTC)
    assert abs((datetime.now(UTC) - reauthenticated_at).total_seconds()) < 10


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
