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
from app.services.refresh_sessions import create_refresh_session

_PASSWORD = "Correct-Horse-Battery-42!"


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


def _setup(
    db_session: Session, *, with_password: bool = True
) -> tuple[RefreshSession, dict[str, str]]:
    user = User(
        email=f"reauth-api-{uuid.uuid4().hex}@example.com",
        display_name="Reauth API Test",
        password_hash=hash_password(_PASSWORD) if with_password else None,
        is_active=True,
        email_verified_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.flush()
    create_refresh_session(db_session, user.id)
    record = db_session.scalar(select(RefreshSession).where(RefreshSession.user_id == user.id))
    assert record is not None
    record.last_used_at = datetime.now(UTC)
    db_session.flush()
    token = tokens.create_access_token(subject=str(user.id), session_id=str(record.id))
    return record, {"Authorization": f"Bearer {token}"}


def test_correct_password_sets_marker(api_client: TestClient, db_session: Session) -> None:
    record, headers = _setup(db_session)
    assert record.reauthenticated_at is None

    response = api_client.post("/api/v1/auth/reauth", json={"password": _PASSWORD}, headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert set(data) == {"reauthenticated_until"}
    until = datetime.fromisoformat(data["reauthenticated_until"])
    if until.tzinfo is None:
        until = until.replace(tzinfo=UTC)
    assert timedelta(minutes=9, seconds=50) < until - datetime.now(UTC) <= timedelta(minutes=10)
    db_session.refresh(record)
    assert record.reauthenticated_at is not None
    assert _PASSWORD not in response.text


def test_wrong_password_is_forbidden_and_marker_unchanged(
    api_client: TestClient, db_session: Session
) -> None:
    record, headers = _setup(db_session)
    response = api_client.post(
        "/api/v1/auth/reauth", json={"password": "Wrong-Password-42!"}, headers=headers
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "invalid_credentials"}
    db_session.refresh(record)
    assert record.reauthenticated_at is None


def test_user_without_password_is_forbidden(api_client: TestClient, db_session: Session) -> None:
    record, headers = _setup(db_session, with_password=False)
    response = api_client.post("/api/v1/auth/reauth", json={"password": _PASSWORD}, headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "invalid_credentials"}
    db_session.refresh(record)
    assert record.reauthenticated_at is None


def test_missing_token_is_unauthenticated(api_client: TestClient) -> None:
    response = api_client.post("/api/v1/auth/reauth", json={"password": _PASSWORD})
    assert response.status_code == 401


def test_revoked_session_is_unauthenticated(api_client: TestClient, db_session: Session) -> None:
    record, headers = _setup(db_session)
    record.revoked_at = datetime.now(UTC)
    db_session.flush()
    response = api_client.post("/api/v1/auth/reauth", json={"password": _PASSWORD}, headers=headers)
    assert response.status_code == 401
    db_session.refresh(record)
    assert record.reauthenticated_at is None


def test_sixth_attempt_is_rate_limited(api_client: TestClient, db_session: Session) -> None:
    _, headers = _setup(db_session)
    for _ in range(5):
        response = api_client.post(
            "/api/v1/auth/reauth", json={"password": "Wrong-Password-42!"}, headers=headers
        )
        assert response.status_code == 403
    response = api_client.post("/api/v1/auth/reauth", json={"password": _PASSWORD}, headers=headers)
    assert response.status_code == 429
    assert int(response.headers["retry-after"]) >= 1


def test_ip_bucket_limits_across_users(api_client: TestClient, db_session: Session) -> None:
    """The per-IP bucket trips on its own when every user stays under their own limit."""
    for _ in range(20):
        _, headers = _setup(db_session)
        response = api_client.post(
            "/api/v1/auth/reauth", json={"password": "Wrong-Password-42!"}, headers=headers
        )
        assert response.status_code == 403
    _, headers = _setup(db_session)
    response = api_client.post("/api/v1/auth/reauth", json={"password": _PASSWORD}, headers=headers)
    assert response.status_code == 429
    assert int(response.headers["retry-after"]) >= 1


def test_untrusted_origin_is_rejected_before_any_work(
    api_client: TestClient, db_session: Session
) -> None:
    record, headers = _setup(db_session)
    response = api_client.post(
        "/api/v1/auth/reauth",
        json={"password": _PASSWORD},
        headers={**headers, "Origin": "https://attacker.example"},
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "Untrusted request origin."}
    db_session.refresh(record)
    assert record.reauthenticated_at is None

    # The rejected request must not have consumed rate-limit budget: five wrong
    # attempts are still allowed afterwards.
    for _ in range(5):
        wrong = api_client.post(
            "/api/v1/auth/reauth", json={"password": "Wrong-Password-42!"}, headers=headers
        )
        assert wrong.status_code == 403


def test_success_response_window_matches_stored_marker(
    api_client: TestClient, db_session: Session
) -> None:
    record, headers = _setup(db_session)
    response = api_client.post("/api/v1/auth/reauth", json={"password": _PASSWORD}, headers=headers)
    assert response.status_code == 200
    until = datetime.fromisoformat(response.json()["reauthenticated_until"])
    if until.tzinfo is None:
        until = until.replace(tzinfo=UTC)
    db_session.refresh(record)
    marker = record.reauthenticated_at
    assert marker is not None
    if marker.tzinfo is None:
        marker = marker.replace(tzinfo=UTC)
    assert until - marker == timedelta(minutes=10)
