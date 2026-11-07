import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.main import app
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.models.user_preferences import UserPreferences
from app.security import tokens
from app.services.rate_limiting import RateLimitResult
from app.services.refresh_sessions import create_refresh_session, hash_refresh_token

_URL = "/api/v1/users/me/preferences"
_DEFAULTS = {"theme": "system", "show_presence": True}


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
        email=f"prefs-{uuid.uuid4().hex}@example.com",
        display_name="Preferences Test",
        password_hash=None,
        is_active=True,
        email_verified_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.flush()
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


def _stored(db_session: Session, user: User):
    return db_session.execute(
        select(
            UserPreferences.theme,
            UserPreferences.show_presence,
            UserPreferences.updated_at,
        ).where(UserPreferences.user_id == user.id)
    ).one_or_none()


def test_get_returns_defaults_when_no_row_exists(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = _make_user(db_session)

    response = api_client.get(_URL, headers=_auth_headers(db_session, user))

    assert response.status_code == 200
    assert response.json() == _DEFAULTS
    assert _stored(db_session, user) is None


def test_get_returns_stored_values(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = _make_user(db_session)
    db_session.add(UserPreferences(user_id=user.id, theme="dark", show_presence=False))
    db_session.flush()

    response = api_client.get(_URL, headers=_auth_headers(db_session, user))

    assert response.status_code == 200
    assert response.json() == {"theme": "dark", "show_presence": False}


def test_get_requires_authentication(api_client: TestClient) -> None:
    response = api_client.get(_URL)

    assert response.status_code == 401


def test_patch_requires_authentication(api_client: TestClient) -> None:
    response = api_client.patch(_URL, json={"theme": "dark"})

    assert response.status_code == 401


def test_patch_theme_only_creates_row_with_default_presence(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = _make_user(db_session)

    response = api_client.patch(
        _URL,
        json={"theme": "dark"},
        headers=_auth_headers(db_session, user),
    )

    assert response.status_code == 200
    assert response.json() == {"theme": "dark", "show_presence": True}
    row = _stored(db_session, user)
    assert row is not None
    assert row.theme == "dark"
    assert row.show_presence is True


def test_patch_presence_only_creates_row_with_default_theme(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = _make_user(db_session)

    response = api_client.patch(
        _URL,
        json={"show_presence": False},
        headers=_auth_headers(db_session, user),
    )

    assert response.status_code == 200
    assert response.json() == {"theme": "system", "show_presence": False}


def test_partial_patch_keeps_the_other_field(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)

    first = api_client.patch(_URL, json={"theme": "light"}, headers=headers)
    second = api_client.patch(_URL, json={"show_presence": False}, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json() == {"theme": "light", "show_presence": False}
    assert api_client.get(_URL, headers=headers).json() == {
        "theme": "light",
        "show_presence": False,
    }


def test_patch_both_fields(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = _make_user(db_session)

    response = api_client.patch(
        _URL,
        json={"theme": "light", "show_presence": False},
        headers=_auth_headers(db_session, user),
    )

    assert response.status_code == 200
    assert response.json() == {"theme": "light", "show_presence": False}


def test_patch_touches_updated_at_on_existing_row(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)
    assert api_client.patch(_URL, json={"theme": "dark"}, headers=headers).status_code == 200

    old = datetime(2000, 1, 1, tzinfo=UTC)
    db_session.execute(
        update(UserPreferences).where(UserPreferences.user_id == user.id).values(updated_at=old)
    )
    db_session.commit()

    response = api_client.patch(_URL, json={"theme": "light"}, headers=headers)

    assert response.status_code == 200
    row = _stored(db_session, user)
    assert row is not None
    assert row.updated_at > old


BAD_BODIES = [
    {},
    {"theme": None},
    {"show_presence": None},
    {"theme": "blue"},
    {"theme": "DARK"},
    {"theme": 1},
    {"show_presence": "yes"},
    {"show_presence": 1},
    {"show_presence": "true"},
    {"extra": True},
    {"theme": "dark", "extra": 1},
]


@pytest.mark.parametrize("body", BAD_BODIES, ids=range(len(BAD_BODIES)))
def test_patch_rejects_invalid_bodies_and_creates_no_row(
    api_client: TestClient,
    db_session: Session,
    body: dict[str, object],
) -> None:
    user = _make_user(db_session)

    response = api_client.patch(_URL, json=body, headers=_auth_headers(db_session, user))

    assert response.status_code == 422
    assert _stored(db_session, user) is None


def test_users_do_not_see_each_others_preferences(
    api_client: TestClient,
    db_session: Session,
) -> None:
    first = _make_user(db_session)
    second = _make_user(db_session)
    first_headers = _auth_headers(db_session, first)
    second_headers = _auth_headers(db_session, second)

    api_client.patch(_URL, json={"theme": "dark", "show_presence": False}, headers=first_headers)

    assert api_client.get(_URL, headers=second_headers).json() == _DEFAULTS
    assert api_client.get(_URL, headers=first_headers).json() == {
        "theme": "dark",
        "show_presence": False,
    }


def test_preferences_route_is_not_shadowed_by_user_lookup(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = _make_user(db_session)

    response = api_client.get(_URL, headers=_auth_headers(db_session, user))

    assert response.status_code == 200
    assert set(response.json()) == {"theme", "show_presence"}


def test_get_returns_429_when_rate_limited(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)
    observed: dict[str, object] = {}

    def deny_request(buckets: list[object]) -> RateLimitResult:
        observed["buckets"] = buckets
        return RateLimitResult(allowed=False, retry_after_seconds=42)

    monkeypatch.setattr("app.api.v1.endpoints.auth.consume_rate_limit_buckets", deny_request)

    response = api_client.get(_URL, headers=headers)

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "42"
    buckets = observed["buckets"]
    assert isinstance(buckets, list)
    assert [(b.scope, b.kind) for b in buckets] == [
        ("users:get-preferences:ip", "ip"),
        ("users:get-preferences:user", "email"),
    ]


def test_patch_returns_429_when_rate_limited_and_changes_nothing(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)
    observed: dict[str, object] = {}

    def deny_request(buckets: list[object]) -> RateLimitResult:
        observed["buckets"] = buckets
        return RateLimitResult(allowed=False, retry_after_seconds=42)

    monkeypatch.setattr("app.api.v1.endpoints.auth.consume_rate_limit_buckets", deny_request)

    response = api_client.patch(_URL, json={"theme": "dark"}, headers=headers)

    assert response.status_code == 429
    buckets = observed["buckets"]
    assert isinstance(buckets, list)
    assert [(b.scope, b.kind) for b in buckets] == [
        ("users:update-preferences:ip", "ip"),
        ("users:update-preferences:user", "email"),
    ]
    assert _stored(db_session, user) is None


@pytest.mark.parametrize("method", ["get", "patch"])
def test_endpoints_fail_closed_when_rate_limit_database_fails(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
) -> None:
    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)

    def fail_limiter(_buckets: list[object]) -> RateLimitResult:
        raise SQLAlchemyError("simulated rate-limit database failure")

    monkeypatch.setattr("app.api.v1.endpoints.auth.consume_rate_limit_buckets", fail_limiter)

    kwargs = {"json": {"theme": "dark"}} if method == "patch" else {}
    response = getattr(api_client, method)(_URL, headers=headers, **kwargs)

    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable."}


def test_patch_returns_503_on_database_error(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)

    def fail_update(*_args: object, **_kwargs: object) -> None:
        raise SQLAlchemyError("simulated database failure")

    monkeypatch.setattr("app.api.v1.endpoints.users.update_preferences", fail_update)

    response = api_client.patch(_URL, json={"theme": "dark"}, headers=headers)

    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable."}


def test_get_returns_503_on_database_error(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = _make_user(db_session)
    headers = _auth_headers(db_session, user)

    def fail_get(*_args: object, **_kwargs: object) -> None:
        raise SQLAlchemyError("simulated database failure")

    monkeypatch.setattr("app.api.v1.endpoints.users.get_preferences", fail_get)

    response = api_client.get(_URL, headers=headers)

    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable."}
