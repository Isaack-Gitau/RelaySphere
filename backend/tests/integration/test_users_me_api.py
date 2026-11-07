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
from app.models.username_claim import UsernameClaim
from app.security import tokens
from app.services.refresh_sessions import create_refresh_session, hash_refresh_token

_URL = "/api/v1/users/me"
_ORIGINAL_NAME = "Profile Test"
_PROFILE_FIELDS = {
    "id",
    "username",
    "display_name",
    "email",
    "email_verified_at",
    "is_active",
    "created_at",
}


@pytest.fixture
def api_client(db_session: Session) -> Generator[TestClient]:
    def override_db_session() -> Generator[Session]:
        yield db_session

    app.dependency_overrides[get_db_session] = override_db_session
    try:
        with TestClient(app, headers={"Origin": "http://localhost:5173"}) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db_session, None)


@pytest.fixture(autouse=True)
def token_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tokens,
        "get_settings",
        lambda: SimpleNamespace(
            access_token_secret="integration-test-secret-at-least-32-characters",
            access_token_expire_minutes=15,
        ),
    )


def _new_username() -> str:
    return f"profile_{uuid.uuid4().hex[:8]}"


def _make_user(db_session: Session, *, username: str | None = None) -> User:
    user = User(
        email=f"users-me-{uuid.uuid4().hex}@example.com",
        display_name=_ORIGINAL_NAME,
        password_hash=None,
        is_active=True,
        email_verified_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.flush()

    if username is not None:
        db_session.add(UsernameClaim(username=username, claim_type="permanent", user_id=user.id))
        db_session.flush()
        db_session.expire(user, ["username_claim"])

    return user


def _auth_headers(db_session: Session, user: User) -> dict[str, str]:
    raw_token = create_refresh_session(db_session, user.id)
    record = db_session.scalar(
        select(RefreshSession).where(RefreshSession.token_hash == hash_refresh_token(raw_token))
    )
    assert record is not None
    record.last_used_at = datetime.now(UTC)
    db_session.flush()
    access_token = tokens.create_access_token(subject=str(user.id), session_id=str(record.id))
    return {"Authorization": f"Bearer {access_token}"}


def test_get_profile_returns_exactly_the_own_profile_fields(
    api_client: TestClient,
    db_session: Session,
) -> None:
    username = _new_username()
    user = _make_user(db_session, username=username)

    response = api_client.get(_URL, headers=_auth_headers(db_session, user))

    assert response.status_code == 200
    data = response.json()
    assert set(data) == _PROFILE_FIELDS
    assert data["id"] == str(user.id)
    assert data["username"] == username
    assert data["display_name"] == _ORIGINAL_NAME
    assert data["email"] == user.email
    assert data["email_verified_at"] is not None
    assert data["is_active"] is True
    assert data["created_at"] is not None


def test_get_profile_username_is_null_without_a_claim(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = _make_user(db_session)

    response = api_client.get(_URL, headers=_auth_headers(db_session, user))

    assert response.status_code == 200
    assert response.json()["username"] is None


def test_get_profile_requires_a_token(api_client: TestClient) -> None:
    response = api_client.get(_URL)

    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials."}


def test_patch_profile_requires_a_token(api_client: TestClient) -> None:
    response = api_client.patch(_URL, json={"display_name": "Anyone"})

    assert response.status_code == 401


def test_patch_trims_and_saves_the_display_name(
    api_client: TestClient,
    db_session: Session,
) -> None:
    username = _new_username()
    user = _make_user(db_session, username=username)
    headers = _auth_headers(db_session, user)

    response = api_client.patch(_URL, json={"display_name": "  New Name  "}, headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert set(data) == _PROFILE_FIELDS
    assert data["display_name"] == "New Name"
    assert data["username"] == username
    assert api_client.get(_URL, headers=headers).json()["display_name"] == "New Name"
    db_session.refresh(user)
    assert user.display_name == "New Name"


def test_patch_with_an_unchanged_name_still_succeeds(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)

    response = api_client.patch(_URL, json={"display_name": _ORIGINAL_NAME}, headers=headers)

    assert response.status_code == 200
    assert response.json()["display_name"] == _ORIGINAL_NAME


def test_patch_accepts_an_eighty_character_name(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)

    response = api_client.patch(_URL, json={"display_name": "a" * 80}, headers=headers)

    assert response.status_code == 200
    assert response.json()["display_name"] == "a" * 80


@pytest.mark.parametrize(
    "body",
    [
        {"display_name": "Valid Name", "email": "other@example.com"},
        {"display_name": "Valid Name", "is_active": False},
        {"display_name": "Valid Name", "email_verified_at": "2026-01-01T00:00:00Z"},
        {"display_name": "Valid Name", "username": "someone_else"},
        {"email": "other@example.com"},
        {"is_active": False},
    ],
    ids=[
        "email-with-name",
        "is-active-with-name",
        "verified-with-name",
        "username-with-name",
        "email-only",
        "is-active-only",
    ],
)
def test_patch_rejects_protected_and_unknown_fields(
    api_client: TestClient,
    db_session: Session,
    body: dict[str, object],
) -> None:
    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)
    original_email = user.email
    original_verified_at = user.email_verified_at

    response = api_client.patch(_URL, json=body, headers=headers)

    assert response.status_code == 422
    db_session.refresh(user)
    assert user.display_name == _ORIGINAL_NAME
    assert user.email == original_email
    assert user.is_active is True
    assert user.email_verified_at == original_verified_at


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"display_name": ""},
        {"display_name": "   "},
        {"display_name": "a" * 81},
        {"display_name": None},
        {"display_name": 123},
    ],
    ids=["empty-body", "empty-name", "blank-name", "name-too-long", "null-name", "number-name"],
)
def test_patch_rejects_invalid_display_names(
    api_client: TestClient,
    db_session: Session,
    body: dict[str, object],
) -> None:
    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)

    response = api_client.patch(_URL, json=body, headers=headers)

    assert response.status_code == 422
    db_session.refresh(user)
    assert user.display_name == _ORIGINAL_NAME


def test_patch_changes_only_the_callers_profile(
    api_client: TestClient,
    db_session: Session,
) -> None:
    caller = _make_user(db_session)
    stranger = _make_user(db_session)
    headers = _auth_headers(db_session, caller)

    response = api_client.patch(_URL, json={"display_name": "Caller Only"}, headers=headers)

    assert response.status_code == 200
    db_session.refresh(caller)
    db_session.refresh(stranger)
    assert caller.display_name == "Caller Only"
    assert stranger.display_name == _ORIGINAL_NAME


def test_eleventh_patch_for_one_user_is_rate_limited(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)
    for number in range(10):
        response = api_client.patch(
            _URL,
            json={"display_name": f"Name {number}"},
            headers=headers,
        )
        assert response.status_code == 200

    response = api_client.patch(_URL, json={"display_name": "Eleventh"}, headers=headers)

    assert response.status_code == 429
    assert int(response.headers["retry-after"]) >= 1
    db_session.refresh(user)
    assert user.display_name == "Name 9"


def test_ip_bucket_limits_patches_across_users(
    api_client: TestClient,
    db_session: Session,
) -> None:
    for number in range(30):
        user = _make_user(db_session)
        response = api_client.patch(
            _URL,
            json={"display_name": f"Name {number}"},
            headers=_auth_headers(db_session, user),
        )
        assert response.status_code == 200

    user = _make_user(db_session)
    response = api_client.patch(
        _URL,
        json={"display_name": "Thirty First"},
        headers=_auth_headers(db_session, user),
    )

    assert response.status_code == 429
    assert int(response.headers["retry-after"]) >= 1
