import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.main import app
from app.models.username_claim import UsernameClaim
from app.security.username_reservations import verify_reservation_token
from app.services.rate_limiting import RateLimitResult


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


def reservation_payload(
    username: str = "mira_njoroge",
    attempt_id: uuid.UUID | None = None,
) -> dict[str, str]:
    return {
        "username": username,
        "registration_attempt_id": str(attempt_id or uuid.uuid4()),
    }


def test_create_username_reservation_returns_201_and_plaintext_token_once(
    api_client: TestClient,
    db_session: Session,
) -> None:
    payload = reservation_payload()

    response = api_client.post(
        "/api/v1/auth/username-reservations",
        json=payload,
    )

    assert response.status_code == 201
    body = response.json()

    assert body["username"] == payload["username"]
    assert uuid.UUID(body["reservation_id"])
    assert len(body["reservation_token"]) == 43
    assert body["expires_at"]

    claim = db_session.scalar(
        select(UsernameClaim).where(UsernameClaim.id == uuid.UUID(body["reservation_id"]))
    )
    assert claim is not None
    assert claim.claim_type == "reservation"
    assert claim.registration_attempt_id == uuid.UUID(payload["registration_attempt_id"])
    assert claim.token_hash != body["reservation_token"]
    assert verify_reservation_token(
        body["reservation_token"],
        claim.token_hash,
    )


def test_create_username_reservation_returns_409_for_reserved_username(
    api_client: TestClient,
) -> None:
    response = api_client.post(
        "/api/v1/auth/username-reservations",
        json=reservation_payload(username="admin"),
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_UNAVAILABLE"}


def test_create_username_reservation_returns_409_for_active_username_claim(
    api_client: TestClient,
    db_session: Session,
) -> None:
    db_session.add(
        UsernameClaim(
            username="already_reserved",
            claim_type="reservation",
            registration_attempt_id=uuid.uuid4(),
            token_hash="a" * 64,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    db_session.commit()

    response = api_client.post(
        "/api/v1/auth/username-reservations",
        json=reservation_payload(username="already_reserved"),
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_UNAVAILABLE"}


def test_create_username_reservation_returns_409_when_attempt_already_reserved(
    api_client: TestClient,
    db_session: Session,
) -> None:
    attempt_id = uuid.uuid4()

    db_session.add(
        UsernameClaim(
            username="first_username",
            claim_type="reservation",
            registration_attempt_id=attempt_id,
            token_hash="b" * 64,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    db_session.commit()

    response = api_client.post(
        "/api/v1/auth/username-reservations",
        json=reservation_payload(
            username="second_username",
            attempt_id=attempt_id,
        ),
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_RESERVATION_EXISTS"}


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"username": "ab", "registration_attempt_id": str(uuid.uuid4())},
        {"username": "Invalid_Name", "registration_attempt_id": str(uuid.uuid4())},
        {"username": "valid_name", "registration_attempt_id": str(uuid.uuid4()), "extra": True},
        {"username": "valid_name", "registration_attempt_id": str(uuid.uuid1())},
    ],
)
def test_create_username_reservation_rejects_invalid_payloads(
    api_client: TestClient,
    payload: dict[str, object],
) -> None:
    response = api_client.post(
        "/api/v1/auth/username-reservations",
        json=payload,
    )

    assert response.status_code == 422


def test_create_username_reservation_returns_429_when_rate_limited(
    api_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny_request(_buckets: list[object]) -> RateLimitResult:
        return RateLimitResult(allowed=False, retry_after_seconds=60)

    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.consume_rate_limit_buckets",
        deny_request,
    )

    response = api_client.post(
        "/api/v1/auth/username-reservations",
        json=reservation_payload(),
    )

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "60"


def test_create_username_reservation_fails_closed_on_database_error(
    api_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_creation(
        _session: Session,
        _username: str,
        _attempt_id: uuid.UUID,
    ) -> None:
        raise SQLAlchemyError("simulated database failure")

    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.create_username_reservation",
        fail_creation,
    )

    response = api_client.post(
        "/api/v1/auth/username-reservations",
        json=reservation_payload(),
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable."}
