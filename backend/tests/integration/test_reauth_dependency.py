from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.dependencies.current_user import require_recent_reauth
from app.db.session import get_db_session
from app.main import app
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.security import tokens
from app.services.refresh_sessions import create_refresh_session

_PATH = "/api/v1/_test/sensitive"


@pytest.fixture
def api_client(db_session: Session) -> Generator[TestClient]:
    """Use the isolated test session and a temporary protected route."""

    def override_db_session() -> Generator[Session]:
        yield db_session

    def sensitive(user: User = Depends(require_recent_reauth)) -> dict[str, str]:  # noqa: B008
        return {"user_id": str(user.id)}

    app.dependency_overrides[get_db_session] = override_db_session
    app.add_api_route(_PATH, sensitive, methods=["GET"])

    try:
        with TestClient(app, headers={"Origin": "http://localhost:5173"}) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db_session, None)
        app.router.routes[:] = [r for r in app.router.routes if getattr(r, "path", "") != _PATH]


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


def _setup(db_session: Session, marker_age: timedelta | None) -> dict[str, str]:
    user = User(
        email=f"reauth-dep-{datetime.now(UTC).timestamp()}@example.com",
        display_name="Reauth Dependency Test",
        password_hash=None,
        is_active=True,
        email_verified_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.flush()
    create_refresh_session(db_session, user.id)
    record = db_session.scalar(select(RefreshSession).where(RefreshSession.user_id == user.id))
    assert record is not None
    record.last_used_at = datetime.now(UTC)
    record.reauthenticated_at = None if marker_age is None else datetime.now(UTC) - marker_age
    db_session.flush()
    token = tokens.create_access_token(subject=str(user.id), session_id=str(record.id))
    return {"Authorization": f"Bearer {token}"}


def test_null_marker_is_denied(api_client: TestClient, db_session: Session) -> None:
    response = api_client.get(_PATH, headers=_setup(db_session, None))
    assert response.status_code == 403
    assert response.json() == {"detail": "reauthentication_required"}


def test_fresh_marker_is_allowed(api_client: TestClient, db_session: Session) -> None:
    response = api_client.get(_PATH, headers=_setup(db_session, timedelta(minutes=1)))
    assert response.status_code == 200


def test_stale_marker_is_denied(api_client: TestClient, db_session: Session) -> None:
    response = api_client.get(_PATH, headers=_setup(db_session, timedelta(minutes=11)))
    assert response.status_code == 403
    assert response.json() == {"detail": "reauthentication_required"}


def test_future_marker_is_denied(api_client: TestClient, db_session: Session) -> None:
    response = api_client.get(_PATH, headers=_setup(db_session, timedelta(minutes=-5)))
    assert response.status_code == 403


def test_missing_token_is_unauthenticated_not_forbidden(api_client: TestClient) -> None:
    response = api_client.get(_PATH)
    assert response.status_code == 401
