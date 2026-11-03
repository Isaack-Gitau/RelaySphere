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
from app.security.passwords import hash_password
from app.services.refresh_sessions import create_refresh_session, hash_refresh_token

_PASSWORD = "Correct-Horse-Battery-42!"
_URL = "/api/v1/auth/sessions/revoke-others"
_CONFIRM = {"confirm": True}


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


def _make_user(db_session: Session, *, with_password: bool = False) -> User:
    user = User(
        email=f"revoke-others-{uuid.uuid4().hex}@example.com",
        display_name="Revoke Others Test",
        password_hash=hash_password(_PASSWORD) if with_password else None,
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
) -> tuple[RefreshSession, dict[str, str]]:
    raw_token = create_refresh_session(db_session, user.id, reauthenticated=reauthenticated)
    record = db_session.scalar(
        select(RefreshSession).where(RefreshSession.token_hash == hash_refresh_token(raw_token))
    )
    assert record is not None
    now = datetime.now(UTC)
    record.last_used_at = now
    if reauth_age is not None:
        record.reauthenticated_at = now - reauth_age
    db_session.flush()
    access_token = tokens.create_access_token(subject=str(user.id), session_id=str(record.id))
    return record, {"Authorization": f"Bearer {access_token}"}


@pytest.mark.parametrize(
    "kwargs",
    [{"reauthenticated": False}, {"reauth_age": timedelta(minutes=11)}],
    ids=["never-reauthenticated", "window-expired"],
)
def test_stale_reauth_is_forbidden_and_revokes_nothing(
    api_client: TestClient, db_session: Session, kwargs: dict[str, object]
) -> None:
    user = _make_user(db_session)
    caller, headers = _add_session(db_session, user, **kwargs)
    other, _ = _add_session(db_session, user)

    response = api_client.post(_URL, json=_CONFIRM, headers=headers)

    assert response.status_code == 403
    assert response.json() == {"detail": "reauthentication_required"}
    db_session.refresh(caller)
    db_session.refresh(other)
    assert caller.revoked_at is None
    assert other.revoked_at is None


def test_fresh_reauth_revokes_only_other_active_sessions(
    api_client: TestClient, db_session: Session
) -> None:
    user = _make_user(db_session)
    first, _ = _add_session(db_session, user)
    caller, headers = _add_session(db_session, user)
    last, _ = _add_session(db_session, user)
    already_revoked, _ = _add_session(db_session, user)
    long_ago = datetime.now(UTC) - timedelta(hours=1)
    already_revoked.revoked_at = long_ago
    db_session.flush()
    marker_before = caller.reauthenticated_at
    assert marker_before is not None

    response = api_client.post(_URL, json=_CONFIRM, headers=headers)

    assert response.status_code == 200
    assert response.json() == {"revoked_count": 2}
    for record in (first, caller, last, already_revoked):
        db_session.refresh(record)
    assert caller.revoked_at is None
    assert caller.reauthenticated_at == marker_before
    assert first.revoked_at is not None
    assert last.revoked_at is not None
    assert already_revoked.revoked_at == long_ago


@pytest.mark.parametrize(
    "body",
    [
        {"confirm": False},
        {},
        {"confirm": "true"},
        {"confirm": 1},
        {"confirm": None},
        {"confirm": True, "extra": 1},
    ],
    ids=["false", "missing", "string", "integer", "null", "extra-field"],
)
def test_confirm_must_be_exactly_true(
    api_client: TestClient, db_session: Session, body: dict[str, object]
) -> None:
    user = _make_user(db_session)
    _, headers = _add_session(db_session, user)
    other, _ = _add_session(db_session, user)

    response = api_client.post(_URL, json=body, headers=headers)

    assert response.status_code == 422
    db_session.refresh(other)
    assert other.revoked_at is None


def test_other_users_sessions_are_untouched(api_client: TestClient, db_session: Session) -> None:
    user = _make_user(db_session)
    _, headers = _add_session(db_session, user)
    mine, _ = _add_session(db_session, user)
    stranger = _make_user(db_session)
    theirs_one, _ = _add_session(db_session, stranger)
    theirs_two, _ = _add_session(db_session, stranger)

    response = api_client.post(_URL, json=_CONFIRM, headers=headers)

    assert response.status_code == 200
    assert response.json() == {"revoked_count": 1}
    for record in (mine, theirs_one, theirs_two):
        db_session.refresh(record)
    assert mine.revoked_at is not None
    assert theirs_one.revoked_at is None
    assert theirs_two.revoked_at is None


def test_revoked_session_token_is_rejected_afterwards(
    api_client: TestClient, db_session: Session
) -> None:
    user = _make_user(db_session)
    _, caller_headers = _add_session(db_session, user)
    _, other_headers = _add_session(db_session, user)

    first = api_client.post(_URL, json=_CONFIRM, headers=caller_headers)
    assert first.status_code == 200

    rejected = api_client.post(_URL, json=_CONFIRM, headers=other_headers)
    assert rejected.status_code == 401


def test_repeat_call_is_idempotent(api_client: TestClient, db_session: Session) -> None:
    user = _make_user(db_session)
    _, headers = _add_session(db_session, user)
    _add_session(db_session, user)

    first = api_client.post(_URL, json=_CONFIRM, headers=headers)
    second = api_client.post(_URL, json=_CONFIRM, headers=headers)

    assert first.status_code == 200
    assert first.json() == {"revoked_count": 1}
    assert second.status_code == 200
    assert second.json() == {"revoked_count": 0}


def test_login_then_revoke_others_flow(api_client: TestClient, db_session: Session) -> None:
    user = _make_user(db_session, with_password=True)
    tokens_by_login = []
    for _ in range(2):
        login = api_client.post(
            "/api/v1/auth/login", json={"email": user.email, "password": _PASSWORD}
        )
        assert login.status_code == 200
        tokens_by_login.append(login.json()["access_token"])
    headers_a = {"Authorization": f"Bearer {tokens_by_login[0]}"}
    headers_b = {"Authorization": f"Bearer {tokens_by_login[1]}"}

    response = api_client.post(_URL, json=_CONFIRM, headers=headers_b)
    assert response.status_code == 200
    assert response.json() == {"revoked_count": 1}

    assert api_client.post(_URL, json=_CONFIRM, headers=headers_a).status_code == 401
    again = api_client.post(_URL, json=_CONFIRM, headers=headers_b)
    assert again.status_code == 200
    assert again.json() == {"revoked_count": 0}


def test_missing_token_is_unauthenticated(api_client: TestClient) -> None:
    response = api_client.post(_URL, json=_CONFIRM)
    assert response.status_code == 401


def test_untrusted_origin_is_rejected_before_any_work(
    api_client: TestClient, db_session: Session
) -> None:
    user = _make_user(db_session)
    _, headers = _add_session(db_session, user)
    other, _ = _add_session(db_session, user)

    response = api_client.post(
        _URL,
        json=_CONFIRM,
        headers={**headers, "Origin": "https://attacker.example"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Untrusted request origin."}
    db_session.refresh(other)
    assert other.revoked_at is None


def test_sixth_call_for_one_user_is_rate_limited(
    api_client: TestClient, db_session: Session
) -> None:
    user = _make_user(db_session)
    _, headers = _add_session(db_session, user)
    for _ in range(5):
        assert api_client.post(_URL, json=_CONFIRM, headers=headers).status_code == 200

    response = api_client.post(_URL, json=_CONFIRM, headers=headers)

    assert response.status_code == 429
    assert int(response.headers["retry-after"]) >= 1


def test_ip_bucket_limits_across_users(api_client: TestClient, db_session: Session) -> None:
    """The per-IP bucket trips on its own when every user stays under their own limit."""
    for _ in range(20):
        user = _make_user(db_session)
        _, headers = _add_session(db_session, user)
        assert api_client.post(_URL, json=_CONFIRM, headers=headers).status_code == 200

    user = _make_user(db_session)
    _, headers = _add_session(db_session, user)
    response = api_client.post(_URL, json=_CONFIRM, headers=headers)

    assert response.status_code == 429
    assert int(response.headers["retry-after"]) >= 1
