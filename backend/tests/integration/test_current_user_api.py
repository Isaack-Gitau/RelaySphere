import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.main import app
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.security import tokens
from app.security.passwords import hash_password
from app.services.refresh_sessions import create_refresh_session

_TEST_SECRET = "integration-test-secret-at-least-32-characters"


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


@pytest.fixture
def token_settings(monkeypatch: pytest.MonkeyPatch) -> str:
    """Configure a predictable signing secret for authentication tests."""
    monkeypatch.setattr(
        tokens,
        "get_settings",
        lambda: SimpleNamespace(
            access_token_secret=_TEST_SECRET,
            access_token_expire_minutes=15,
        ),
    )
    return _TEST_SECRET


def create_user(
    db_session: Session,
    *,
    is_active: bool = True,
    verified: bool = True,
) -> User:
    """Create a user for an isolated current-user API test."""
    user = User(
        email=f"{uuid.uuid4().hex}@example.com",
        display_name="Current User Test",
        password_hash=hash_password("Correct-Horse-Battery-42!"),
        is_active=is_active,
        email_verified_at=datetime.now(UTC) if verified else None,
    )

    db_session.add(user)
    db_session.flush()

    return user


def create_signed_token(
    subject: str,
    *,
    token_type: str = "access",
    expired: bool = False,
    secret: str = _TEST_SECRET,
) -> str:
    """Create a signed test token with configurable claims."""
    now = datetime.now(UTC)

    issued_at = now - timedelta(hours=2) if expired else now
    expires_at = now - timedelta(hours=1) if expired else now + timedelta(minutes=15)

    return jwt.encode(
        {
            "sub": subject,
            "sid": str(uuid.uuid4()),
            "type": token_type,
            "iat": issued_at,
            "exp": expires_at,
        },
        secret,
        algorithm="HS256",
    )


def create_active_session(db_session: Session, user: User) -> str:
    """Create a recent server-managed session for an access-token test."""
    create_refresh_session(db_session, user.id)
    record = db_session.scalar(select(RefreshSession).where(RefreshSession.user_id == user.id))
    assert record is not None
    record.last_used_at = datetime.now(UTC)
    db_session.flush()
    return str(record.id)


def test_current_user_returns_authenticated_user(
    api_client: TestClient,
    db_session: Session,
    token_settings: str,
) -> None:
    """Return safe account details for a valid access token."""
    user = create_user(db_session)
    session_id = create_active_session(db_session, user)
    access_token = tokens.create_access_token(
        subject=str(user.id),
        session_id=session_id,
    )

    response = api_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200

    data = response.json()
    assert data["id"] == str(user.id)
    assert data["email"] == user.email
    assert data["display_name"] == user.display_name
    assert data["is_active"] is True
    assert data["email_verified_at"] is not None
    assert data["created_at"] is not None

    assert "password" not in data
    assert "password_hash" not in data
    assert "access_token" not in data


def test_current_user_rejects_missing_token(
    api_client: TestClient,
) -> None:
    """Reject requests without bearer authentication."""
    response = api_client.get("/api/v1/auth/me")

    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials."}
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "token_kind",
    [
        "malformed",
        "expired",
        "wrong-type",
        "invalid-subject",
        "wrong-secret",
    ],
)
def test_current_user_rejects_invalid_tokens(
    api_client: TestClient,
    token_settings: str,
    token_kind: str,
) -> None:
    """Reject malformed, expired, incorrectly typed, or invalid tokens."""
    if token_kind == "malformed":
        access_token = "not-a-valid-jwt"
    elif token_kind == "expired":
        access_token = create_signed_token(
            str(uuid.uuid4()),
            expired=True,
        )
    elif token_kind == "wrong-type":
        access_token = create_signed_token(
            str(uuid.uuid4()),
            token_type="refresh",
        )
    elif token_kind == "invalid-subject":
        access_token = create_signed_token("not-a-uuid")
    else:
        access_token = create_signed_token(
            str(uuid.uuid4()),
            secret="a-different-test-secret-that-is-long-enough",
        )

    response = api_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_current_user_rejects_nonexistent_user(
    api_client: TestClient,
    token_settings: str,
) -> None:
    """Reject a validly signed token whose user does not exist."""
    access_token = tokens.create_access_token(
        subject=str(uuid.uuid4()),
        session_id=str(uuid.uuid4()),
    )

    response = api_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    ("is_active", "verified"),
    [
        (False, True),
        (True, False),
        (False, False),
    ],
    ids=[
        "inactive-account",
        "unverified-account",
        "inactive-and-unverified",
    ],
)
def test_current_user_rejects_unavailable_accounts(
    api_client: TestClient,
    db_session: Session,
    token_settings: str,
    is_active: bool,
    verified: bool,
) -> None:
    """Reject inactive or unverified accounts even with valid tokens."""
    user = create_user(
        db_session,
        is_active=is_active,
        verified=verified,
    )
    session_id = create_active_session(db_session, user)
    access_token = tokens.create_access_token(
        subject=str(user.id),
        session_id=session_id,
    )

    response = api_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
