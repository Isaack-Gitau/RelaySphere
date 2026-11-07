import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
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

_URL = "/api/v1/users/me/username"
_PROFILE_URL = "/api/v1/users/me"
_PROFILE_FIELDS = {
    "id",
    "username",
    "display_name",
    "email",
    "email_verified_at",
    "is_active",
    "created_at",
}
_DISPLAY_NAME = "Username Change Test"
_LONG_AGO = timedelta(days=31)
_RATE_LIMIT_DETAIL = "Too many requests. Please try again later."


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


def _new_name() -> str:
    return f"chg_{uuid.uuid4().hex[:8]}"


def _make_user(
    db_session: Session,
    *,
    username: str | None = None,
    claim_age: timedelta = _LONG_AGO,
) -> User:
    user = User(
        email=f"username-change-api-{uuid.uuid4().hex}@example.com",
        display_name=_DISPLAY_NAME,
        password_hash=None,
        is_active=True,
        email_verified_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.flush()

    if username is not None:
        db_session.add(
            UsernameClaim(
                username=username,
                claim_type="permanent",
                user_id=user.id,
                created_at=datetime.now(UTC) - claim_age,
            )
        )
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


def _permanent_usernames(db_session: Session, user_id: uuid.UUID) -> list[str]:
    return list(
        db_session.scalars(
            select(UsernameClaim.username).where(
                UsernameClaim.user_id == user_id,
                UsernameClaim.claim_type == "permanent",
            )
        ).all()
    )


def test_change_returns_the_profile_with_the_new_name(
    api_client: TestClient,
    db_session: Session,
) -> None:
    new_name = _new_name()
    user = _make_user(db_session, username=_new_name())
    headers = _auth_headers(db_session, user)

    response = api_client.put(_URL, json={"username": new_name}, headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert set(data) == _PROFILE_FIELDS
    assert data["id"] == str(user.id)
    assert data["username"] == new_name
    assert data["display_name"] == _DISPLAY_NAME
    assert api_client.get(_PROFILE_URL, headers=headers).json()["username"] == new_name


def test_old_name_is_burned_into_a_reserved_claim(
    api_client: TestClient,
    db_session: Session,
) -> None:
    old_name = _new_name()
    user = _make_user(db_session, username=old_name)
    headers = _auth_headers(db_session, user)

    response = api_client.put(_URL, json={"username": _new_name()}, headers=headers)

    assert response.status_code == 200
    row = db_session.execute(
        select(UsernameClaim.claim_type, UsernameClaim.user_id).where(
            UsernameClaim.username == old_name
        )
    ).one()
    assert row.claim_type == "reserved"
    assert row.user_id is None


def test_user_without_a_claim_can_set_a_username(
    api_client: TestClient,
    db_session: Session,
) -> None:
    new_name = _new_name()
    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)

    response = api_client.put(_URL, json={"username": new_name}, headers=headers)

    assert response.status_code == 200
    assert response.json()["username"] == new_name
    assert _permanent_usernames(db_session, user.id) == [new_name]


def test_requesting_the_current_name_is_a_successful_no_op(
    api_client: TestClient,
    db_session: Session,
) -> None:
    name = _new_name()
    user = _make_user(db_session, username=name, claim_age=timedelta(days=1))
    headers = _auth_headers(db_session, user)

    response = api_client.put(_URL, json={"username": name}, headers=headers)

    assert response.status_code == 200
    assert response.json()["username"] == name
    assert _permanent_usernames(db_session, user.id) == [name]


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"username": ""},
        {"username": "ab"},
        {"username": "Alice"},
        {"username": "ab__cd"},
        {"username": "a" * 31},
        {"username": 123},
        {"username": None},
        {"username": "valid_name", "email": "other@example.com"},
        {"username": "valid_name", "display_name": "Other Name"},
    ],
    ids=[
        "empty-body",
        "empty-name",
        "too-short",
        "uppercase",
        "double-underscore",
        "too-long",
        "number",
        "null",
        "extra-email",
        "extra-display-name",
    ],
)
def test_invalid_bodies_are_rejected(
    api_client: TestClient,
    db_session: Session,
    body: dict[str, object],
) -> None:
    old_name = _new_name()
    user = _make_user(db_session, username=old_name)
    headers = _auth_headers(db_session, user)

    response = api_client.put(_URL, json=body, headers=headers)

    assert response.status_code == 422
    assert _permanent_usernames(db_session, user.id) == [old_name]


def test_change_requires_a_token(api_client: TestClient) -> None:
    response = api_client.put(_URL, json={"username": _new_name()})

    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials."}


@pytest.mark.parametrize("kind", ["other-users-name", "seeded-reserved-name"])
def test_unavailable_name_returns_409(
    api_client: TestClient,
    db_session: Session,
    kind: str,
) -> None:
    old_name = _new_name()
    user = _make_user(db_session, username=old_name)
    headers = _auth_headers(db_session, user)
    if kind == "seeded-reserved-name":
        target = "admin"
    else:
        target = _new_name()
        _make_user(db_session, username=target)

    response = api_client.put(_URL, json={"username": target}, headers=headers)

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_UNAVAILABLE"}
    assert _permanent_usernames(db_session, user.id) == [old_name]


def test_recent_claim_returns_429_with_retry_after(
    api_client: TestClient,
    db_session: Session,
) -> None:
    old_name = _new_name()
    user = _make_user(db_session, username=old_name, claim_age=timedelta(days=1))
    headers = _auth_headers(db_session, user)

    response = api_client.put(_URL, json={"username": _new_name()}, headers=headers)

    assert response.status_code == 429
    assert response.json() == {"detail": "USERNAME_CHANGE_COOLDOWN"}
    assert abs(int(response.headers["retry-after"]) - 29 * 86400) < 600
    assert _permanent_usernames(db_session, user.id) == [old_name]


def test_cooldown_wins_over_an_unavailable_name(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = _make_user(db_session, username=_new_name(), claim_age=timedelta(days=1))
    headers = _auth_headers(db_session, user)

    response = api_client.put(_URL, json={"username": "admin"}, headers=headers)

    assert response.status_code == 429
    assert response.json() == {"detail": "USERNAME_CHANGE_COOLDOWN"}


def test_sixth_attempt_for_one_user_is_rate_limited(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)
    for _ in range(5):
        response = api_client.put(_URL, json={"username": "admin"}, headers=headers)
        assert response.status_code == 409

    response = api_client.put(_URL, json={"username": "admin"}, headers=headers)

    assert response.status_code == 429
    assert response.json() == {"detail": _RATE_LIMIT_DETAIL}
    assert int(response.headers["retry-after"]) >= 1


def test_ip_bucket_limits_attempts_across_users(
    api_client: TestClient,
    db_session: Session,
) -> None:
    for _ in range(20):
        user = _make_user(db_session)
        headers = _auth_headers(db_session, user)
        response = api_client.put(_URL, json={"username": "admin"}, headers=headers)
        assert response.status_code == 409

    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)
    response = api_client.put(_URL, json={"username": "admin"}, headers=headers)

    assert response.status_code == 429
    assert response.json() == {"detail": _RATE_LIMIT_DETAIL}
    assert int(response.headers["retry-after"]) >= 1


def test_change_affects_only_the_caller(
    api_client: TestClient,
    db_session: Session,
) -> None:
    caller = _make_user(db_session, username=_new_name())
    stranger_name = _new_name()
    stranger = _make_user(db_session, username=stranger_name)
    headers = _auth_headers(db_session, caller)

    response = api_client.put(_URL, json={"username": _new_name()}, headers=headers)

    assert response.status_code == 200
    assert _permanent_usernames(db_session, stranger.id) == [stranger_name]
