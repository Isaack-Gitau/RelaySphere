import uuid
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
from app.security.tokens import create_access_token, decode_access_token
from app.services.refresh_sessions import (
    create_refresh_session,
    hash_refresh_token,
)


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


@pytest.fixture
def token_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use a test signing secret for access-token creation and validation."""
    from app.security import tokens

    monkeypatch.setattr(
        tokens,
        "get_settings",
        lambda: SimpleNamespace(
            access_token_secret="integration-test-secret-at-least-32-characters",
            access_token_expire_minutes=15,
        ),
    )


def create_verified_user(session: Session) -> User:
    """Create an active, verified user for a refresh API test."""
    user = User(
        email=f"refresh-api-{uuid.uuid4().hex}@example.com",
        display_name="Refresh API Test User",
        password_hash=None,
        is_active=True,
        email_verified_at=datetime.now(UTC),
    )
    session.add(user)
    session.flush()
    return user


def test_refresh_rotates_cookie_and_returns_access_token(
    api_client: TestClient,
    db_session: Session,
    token_settings: None,
) -> None:
    user = create_verified_user(db_session)
    original_token = create_refresh_session(db_session, user.id)
    original_record = db_session.scalar(
        select(RefreshSession).where(RefreshSession.user_id == user.id)
    )
    assert original_record is not None
    original_expires_at = original_record.expires_at

    api_client.cookies.set("relaysphere_refresh", original_token)
    response = api_client.post("/api/v1/auth/refresh")

    assert response.status_code == 200
    data = response.json()
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 900

    claims = decode_access_token(data["access_token"])
    assert claims["sub"] == str(user.id)
    assert claims["type"] == "access"

    cookie = response.headers.get("set-cookie", "")
    assert "relaysphere_refresh=" in cookie
    assert "httponly" in cookie.lower()
    assert "samesite=lax" in cookie.lower()
    assert "path=/api/v1/auth" in cookie.lower()
    max_age = int(cookie.lower().split("max-age=", 1)[1].split(";", 1)[0])

    record = db_session.scalar(select(RefreshSession).where(RefreshSession.user_id == user.id))
    assert record is not None
    assert record.expires_at == original_expires_at
    expires_at = record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    remaining_seconds = int((expires_at - datetime.now(UTC)).total_seconds())
    assert 0 < max_age <= remaining_seconds
    assert record.token_hash != hash_refresh_token(original_token)
    assert record.revoked_at is None


def test_refresh_rejects_missing_cookie(
    api_client: TestClient,
) -> None:
    response = api_client.post("/api/v1/auth/refresh")

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired refresh session."}


def test_refresh_rejects_unknown_token_without_details(
    api_client: TestClient,
) -> None:
    api_client.cookies.set("relaysphere_refresh", "unknown-refresh-token")
    response = api_client.post("/api/v1/auth/refresh")

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired refresh session."}


def test_replayed_refresh_token_revokes_session(
    api_client: TestClient,
    db_session: Session,
    token_settings: None,
) -> None:
    user = create_verified_user(db_session)
    original_token = create_refresh_session(db_session, user.id)

    api_client.cookies.set("relaysphere_refresh", original_token)
    first_response = api_client.post("/api/v1/auth/refresh")
    assert first_response.status_code == 200

    # Restore the consumed token to simulate a replay from a stolen copy.
    api_client.cookies.set("relaysphere_refresh", original_token)
    replay_response = api_client.post("/api/v1/auth/refresh")

    assert replay_response.status_code == 401
    assert replay_response.json() == {"detail": "Invalid or expired refresh session."}

    record = db_session.scalar(select(RefreshSession).where(RefreshSession.user_id == user.id))
    assert record is not None
    assert record.revoked_at is not None


def test_logout_revokes_current_refresh_session(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = create_verified_user(db_session)
    original_token = create_refresh_session(db_session, user.id)

    api_client.cookies.set("relaysphere_refresh", original_token)
    response = api_client.post("/api/v1/auth/logout")

    assert response.status_code == 200
    assert response.json() == {"message": "Logged out."}

    record = db_session.scalar(select(RefreshSession).where(RefreshSession.user_id == user.id))
    assert record is not None
    assert record.revoked_at is not None

    cookie = response.headers.get("set-cookie", "").lower()
    assert "relaysphere_refresh=" in cookie
    assert "max-age=0" in cookie
    assert "path=/api/v1/auth" in cookie
    assert "httponly" in cookie


def test_logout_succeeds_without_refresh_cookie(
    api_client: TestClient,
) -> None:
    response = api_client.post("/api/v1/auth/logout")

    assert response.status_code == 200
    assert response.json() == {"message": "Logged out."}

    cookie = response.headers.get("set-cookie", "").lower()
    assert "relaysphere_refresh=" in cookie
    assert "max-age=0" in cookie
    assert "path=/api/v1/auth" in cookie


def test_logout_succeeds_with_unknown_refresh_token(
    api_client: TestClient,
) -> None:
    api_client.cookies.set("relaysphere_refresh", "unknown-refresh-token")
    response = api_client.post("/api/v1/auth/logout")

    assert response.status_code == 200
    assert response.json() == {"message": "Logged out."}

    cookie = response.headers.get("set-cookie", "").lower()
    assert "relaysphere_refresh=" in cookie
    assert "max-age=0" in cookie


def test_logout_invalidates_access_token_immediately(
    api_client: TestClient,
    db_session: Session,
    token_settings: None,
) -> None:
    """Reject an access token as soon as its refresh session is logged out."""
    user = create_verified_user(db_session)
    refresh_token = create_refresh_session(db_session, user.id)

    record = db_session.scalar(
        select(RefreshSession).where(RefreshSession.token_hash == hash_refresh_token(refresh_token))
    )
    assert record is not None

    access_token = create_access_token(
        subject=str(user.id),
        session_id=str(record.id),
    )
    headers = {"Authorization": f"Bearer {access_token}"}

    before_logout = api_client.get("/api/v1/auth/me", headers=headers)
    assert before_logout.status_code == 200

    api_client.cookies.set("relaysphere_refresh", refresh_token)
    logout_response = api_client.post("/api/v1/auth/logout")
    assert logout_response.status_code == 200

    after_logout = api_client.get("/api/v1/auth/me", headers=headers)
    assert after_logout.status_code == 401


def test_logout_does_not_revoke_another_device_session(
    api_client: TestClient,
    db_session: Session,
    token_settings: None,
) -> None:
    """Logging out one device must leave another device's session active."""
    user = create_verified_user(db_session)

    first_refresh_token = create_refresh_session(db_session, user.id)
    second_refresh_token = create_refresh_session(db_session, user.id)

    first_record = db_session.scalar(
        select(RefreshSession).where(
            RefreshSession.token_hash == hash_refresh_token(first_refresh_token)
        )
    )
    second_record = db_session.scalar(
        select(RefreshSession).where(
            RefreshSession.token_hash == hash_refresh_token(second_refresh_token)
        )
    )
    assert first_record is not None
    assert second_record is not None
    assert first_record.id != second_record.id

    second_access_token = create_access_token(
        subject=str(user.id),
        session_id=str(second_record.id),
    )

    api_client.cookies.set("relaysphere_refresh", first_refresh_token)
    logout_response = api_client.post("/api/v1/auth/logout")
    assert logout_response.status_code == 200

    db_session.refresh(first_record)
    db_session.refresh(second_record)

    assert first_record.revoked_at is not None
    assert second_record.revoked_at is None

    second_device_response = api_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {second_access_token}"},
    )
    assert second_device_response.status_code == 200
