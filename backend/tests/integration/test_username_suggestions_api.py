import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.main import app
from app.models.user import User
from app.models.username_claim import UsernameClaim


@pytest.fixture
def api_client(db_session: Session) -> Generator[TestClient]:
    """Use the isolated integration-test session for HTTP requests."""

    def override_db_session() -> Generator[Session]:
        yield db_session

    app.dependency_overrides[get_db_session] = override_db_session

    try:
        with TestClient(app, headers={"Origin": "http://localhost:5173"}) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db_session, None)


def count_reservations(session: Session) -> int:
    """Count temporary username reservations."""
    return session.scalar(
        select(func.count())
        .select_from(UsernameClaim)
        .where(UsernameClaim.claim_type == "reservation")
    ) or 0


def test_username_suggestions_returns_available_candidates(
    api_client: TestClient,
    db_session: Session,
) -> None:
    reservations_before = count_reservations(db_session)

    response = api_client.post(
        "/api/v1/auth/username-suggestions",
        json={"display_name": "Mira Njoroge"},
    )

    assert response.status_code == 200
    suggestions = response.json()["suggestions"]

    assert len(suggestions) == 5
    assert suggestions[0] == "mira_njoroge"
    assert len(set(suggestions)) == len(suggestions)
    assert count_reservations(db_session) == reservations_before


def test_username_suggestions_excludes_reserved_usernames(
    api_client: TestClient,
) -> None:
    response = api_client.post(
        "/api/v1/auth/username-suggestions",
        json={"display_name": "Admin"},
    )

    assert response.status_code == 200
    assert "admin" not in response.json()["suggestions"]


def test_username_suggestions_excludes_permanent_and_active_claims_but_allows_expired(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = User(
        email=f"username-suggestions-{uuid.uuid4().hex}@example.com",
        display_name="Username Suggestions Test",
        password_hash=None,
        is_active=True,
        email_verified_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.flush()

    now = datetime.now(UTC)

    db_session.add_all(
        [
            UsernameClaim(
                username="sample_user",
                claim_type="permanent",
                user_id=user.id,
            ),
            UsernameClaim(
                username="sample_user2",
                claim_type="reservation",
                registration_attempt_id=uuid.uuid4(),
                token_hash="a" * 64,
                expires_at=now + timedelta(minutes=5),
            ),
            UsernameClaim(
                username="sample_user3",
                claim_type="reservation",
                registration_attempt_id=uuid.uuid4(),
                token_hash="b" * 64,
                expires_at=now - timedelta(minutes=5),
            ),
        ]
    )
    db_session.flush()

    response = api_client.post(
        "/api/v1/auth/username-suggestions",
        json={"display_name": "Sample User"},
    )

    assert response.status_code == 200
    suggestions = response.json()["suggestions"]

    assert "sample_user" not in suggestions
    assert "sample_user2" not in suggestions
    assert "sample_user3" in suggestions

    # Suggestion generation must not delete expired reservations.
    expired_claim = db_session.scalar(
        select(UsernameClaim).where(UsernameClaim.username == "sample_user3")
    )
    assert expired_claim is not None
    assert expired_claim.claim_type == "reservation"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"display_name": ""},
        {"display_name": "   "},
        {"display_name": "A" * 81},
        {"display_name": "Valid Name", "unexpected": "field"},
    ],
)
def test_username_suggestions_rejects_invalid_requests(
    api_client: TestClient,
    payload: dict[str, str],
) -> None:
    response = api_client.post(
        "/api/v1/auth/username-suggestions",
        json=payload,
    )

    assert response.status_code == 422


def test_username_suggestions_fails_closed_when_database_query_fails(
    api_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_suggestions(
        _session: Session,
        _display_name: str,
    ) -> list[str]:
        raise SQLAlchemyError("simulated username query failure")

    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.suggest_usernames",
        fail_suggestions,
    )

    response = api_client.post(
        "/api/v1/auth/username-suggestions",
        json={"display_name": "Mira Njoroge"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable."}
