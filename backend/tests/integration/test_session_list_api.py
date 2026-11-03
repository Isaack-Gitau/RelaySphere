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
from app.security import tokens
from app.services.refresh_sessions import create_refresh_session, hash_refresh_token

_URL = "/api/v1/auth/sessions"
_ITEM_KEYS = {
    "id",
    "created_at",
    "last_used_at",
    "expires_at",
    "reauthenticated_until",
    "is_current",
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


def _make_user(db_session: Session) -> User:
    user = User(
        email=f"session-list-{uuid.uuid4().hex}@example.com",
        display_name="Session List Test",
        password_hash=None,
        is_active=True,
        email_verified_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.flush()
    return user


def _add_session(
    db_session: Session,
    user: User,
    *,
    reauthenticated: bool = True,
    reauth_age: timedelta | None = None,
    last_used_ago: timedelta = timedelta(0),
) -> tuple[RefreshSession, dict[str, str]]:
    raw_token = create_refresh_session(db_session, user.id, reauthenticated=reauthenticated)
    record = db_session.scalar(
        select(RefreshSession).where(RefreshSession.token_hash == hash_refresh_token(raw_token))
    )
    assert record is not None
    now = datetime.now(UTC)
    record.last_used_at = now - last_used_ago
    if reauth_age is not None:
        record.reauthenticated_at = now - reauth_age
    db_session.flush()
    access_token = tokens.create_access_token(subject=str(user.id), session_id=str(record.id))
    return record, {"Authorization": f"Bearer {access_token}"}


def _aware(value: datetime | str) -> datetime:
    parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def test_lists_only_the_callers_active_sessions(
    api_client: TestClient, db_session: Session
) -> None:
    user = _make_user(db_session)
    caller, headers = _add_session(db_session, user)
    good_other, _ = _add_session(db_session, user)
    revoked, _ = _add_session(db_session, user)
    revoked.revoked_at = datetime.now(UTC)
    absolute_expired, _ = _add_session(db_session, user)
    absolute_expired.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    _add_session(db_session, user, last_used_ago=timedelta(days=3650))
    stranger = _make_user(db_session)
    _add_session(db_session, stranger)
    db_session.flush()

    response = api_client.get(_URL, headers=headers)

    assert response.status_code == 200
    listed = {item["id"] for item in response.json()["sessions"]}
    assert listed == {str(caller.id), str(good_other.id)}


def test_current_session_is_first_and_others_follow_by_last_use(
    api_client: TestClient, db_session: Session
) -> None:
    user = _make_user(db_session)
    used_30s_ago, _ = _add_session(db_session, user, last_used_ago=timedelta(seconds=30))
    caller, headers = _add_session(db_session, user, last_used_ago=timedelta(seconds=60))
    used_10s_ago, _ = _add_session(db_session, user, last_used_ago=timedelta(seconds=10))
    used_20s_ago, _ = _add_session(db_session, user, last_used_ago=timedelta(seconds=20))

    response = api_client.get(_URL, headers=headers)

    assert response.status_code == 200
    items = response.json()["sessions"]
    assert [item["id"] for item in items] == [
        str(caller.id),
        str(used_10s_ago.id),
        str(used_20s_ago.id),
        str(used_30s_ago.id),
    ]
    assert [item["is_current"] for item in items] == [True, False, False, False]


def test_response_exposes_only_safe_fields(api_client: TestClient, db_session: Session) -> None:
    user = _make_user(db_session)
    caller, headers = _add_session(db_session, user)
    other, _ = _add_session(db_session, user)

    response = api_client.get(_URL, headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"sessions"}
    assert len(body["sessions"]) == 2
    for item in body["sessions"]:
        assert set(item) == _ITEM_KEYS
    for record in (caller, other):
        assert record.token_hash not in response.text


def test_reauthenticated_until_reflects_each_sessions_window(
    api_client: TestClient, db_session: Session
) -> None:
    user = _make_user(db_session)
    caller, headers = _add_session(db_session, user)
    stale, _ = _add_session(db_session, user, reauth_age=timedelta(minutes=11))
    never, _ = _add_session(db_session, user, reauthenticated=False)
    recent, _ = _add_session(db_session, user, reauth_age=timedelta(minutes=2))

    response = api_client.get(_URL, headers=headers)

    assert response.status_code == 200
    items = {item["id"]: item for item in response.json()["sessions"]}
    assert items[str(stale.id)]["reauthenticated_until"] is None
    assert items[str(never.id)]["reauthenticated_until"] is None
    for record in (caller, recent):
        db_session.refresh(record)
        assert record.reauthenticated_at is not None
        until = _aware(items[str(record.id)]["reauthenticated_until"])
        assert until - _aware(record.reauthenticated_at) == timedelta(minutes=10)


def test_list_is_capped_at_fifty_sessions(api_client: TestClient, db_session: Session) -> None:
    user = _make_user(db_session)
    caller, headers = _add_session(db_session, user, last_used_ago=timedelta(seconds=120))
    others = [
        _add_session(db_session, user, last_used_ago=timedelta(seconds=index))[0]
        for index in range(1, 52)
    ]

    response = api_client.get(_URL, headers=headers)

    assert response.status_code == 200
    items = response.json()["sessions"]
    assert len(items) == 50
    assert items[0]["id"] == str(caller.id)
    expected = {str(caller.id)} | {str(record.id) for record in others[:49]}
    assert {item["id"] for item in items} == expected


def test_missing_token_is_unauthenticated(api_client: TestClient) -> None:
    response = api_client.get(_URL)
    assert response.status_code == 401


def test_revoked_session_is_unauthenticated(api_client: TestClient, db_session: Session) -> None:
    user = _make_user(db_session)
    caller, headers = _add_session(db_session, user)
    caller.revoked_at = datetime.now(UTC)
    db_session.flush()

    response = api_client.get(_URL, headers=headers)

    assert response.status_code == 401
