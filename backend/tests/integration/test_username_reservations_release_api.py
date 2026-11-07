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
from app.models.username_claim import UsernameClaim
from app.security.username_reservations import generate_reservation_token
from app.services.rate_limiting import RateLimitResult

BASE = "/api/v1/auth/username-reservations"


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


def make_reservation(api_client: TestClient, username: str) -> tuple[str, str, str]:
    attempt_id = str(uuid.uuid4())
    response = api_client.post(
        BASE,
        json={"username": username, "registration_attempt_id": attempt_id},
    )
    assert response.status_code == 201
    body = response.json()
    return body["reservation_id"], attempt_id, body["reservation_token"]


def release(
    api_client: TestClient,
    reservation_id: str,
    attempt_id: str,
    token: str,
):
    return api_client.request(
        "DELETE",
        f"{BASE}/{reservation_id}",
        json={"registration_attempt_id": attempt_id, "reservation_token": token},
    )


def row_count(db_session: Session, reservation_id: str) -> int:
    statement = (
        select(func.count())
        .select_from(UsernameClaim)
        .where(UsernameClaim.id == uuid.UUID(reservation_id))
    )
    return db_session.scalar(statement) or 0


def test_release_returns_204_deletes_row_and_frees_username(
    api_client: TestClient,
    db_session: Session,
) -> None:
    reservation_id, attempt_id, token = make_reservation(api_client, "release_target")

    response = release(api_client, reservation_id, attempt_id, token)

    assert response.status_code == 204
    assert response.content == b""

    # Query the shared session only after the second request. An open autobegun
    # transaction would make the create endpoint's session.begin() fail with 503.
    again = api_client.post(
        BASE,
        json={"username": "release_target", "registration_attempt_id": str(uuid.uuid4())},
    )
    assert again.status_code == 201
    assert row_count(db_session, reservation_id) == 0


def test_release_with_wrong_token_is_invalid_and_keeps_row(
    api_client: TestClient,
    db_session: Session,
) -> None:
    reservation_id, attempt_id, _token = make_reservation(api_client, "wrong_token_user")

    response = release(api_client, reservation_id, attempt_id, generate_reservation_token())

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_RESERVATION_INVALID"}
    assert row_count(db_session, reservation_id) == 1


def test_release_with_wrong_attempt_id_is_invalid_and_keeps_row(
    api_client: TestClient,
    db_session: Session,
) -> None:
    reservation_id, _attempt_id, token = make_reservation(api_client, "wrong_attempt_user")

    response = release(api_client, reservation_id, str(uuid.uuid4()), token)

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_RESERVATION_INVALID"}
    assert row_count(db_session, reservation_id) == 1


def test_release_with_unknown_reservation_id_is_invalid(api_client: TestClient) -> None:
    response = release(
        api_client,
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        generate_reservation_token(),
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_RESERVATION_INVALID"}


def test_release_leaves_another_attempts_reservation_untouched(
    api_client: TestClient,
    db_session: Session,
) -> None:
    first_id, first_attempt, first_token = make_reservation(api_client, "first_release_user")
    second_id, _second_attempt, _second_token = make_reservation(api_client, "second_release_user")

    assert release(api_client, first_id, first_attempt, first_token).status_code == 204

    assert row_count(db_session, first_id) == 0
    assert row_count(db_session, second_id) == 1


def test_release_of_expired_reservation_reports_expired_and_keeps_row(
    api_client: TestClient,
    db_session: Session,
) -> None:
    reservation_id, attempt_id, token = make_reservation(api_client, "expired_release_user")
    claim = db_session.scalar(
        select(UsernameClaim).where(UsernameClaim.id == uuid.UUID(reservation_id))
    )
    assert claim is not None
    claim.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()

    response = release(api_client, reservation_id, attempt_id, token)

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_RESERVATION_EXPIRED"}
    assert row_count(db_session, reservation_id) == 1


def test_expired_reservation_with_wrong_token_does_not_reveal_expiry(
    api_client: TestClient,
    db_session: Session,
) -> None:
    reservation_id, attempt_id, _token = make_reservation(api_client, "hidden_expiry_user")
    claim = db_session.scalar(
        select(UsernameClaim).where(UsernameClaim.id == uuid.UUID(reservation_id))
    )
    assert claim is not None
    claim.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()

    response = release(api_client, reservation_id, attempt_id, generate_reservation_token())

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_RESERVATION_INVALID"}


def test_repeat_release_is_invalid(api_client: TestClient) -> None:
    reservation_id, attempt_id, token = make_reservation(api_client, "repeat_release_user")

    assert release(api_client, reservation_id, attempt_id, token).status_code == 204

    second = release(api_client, reservation_id, attempt_id, token)
    assert second.status_code == 409
    assert second.json() == {"detail": "USERNAME_RESERVATION_INVALID"}


def test_release_cannot_remove_a_reserved_system_username(
    api_client: TestClient,
    db_session: Session,
) -> None:
    reserved = db_session.scalar(select(UsernameClaim).where(UsernameClaim.username == "admin"))
    assert reserved is not None

    response = release(
        api_client,
        str(reserved.id),
        str(uuid.uuid4()),
        generate_reservation_token(),
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_RESERVATION_INVALID"}
    assert row_count(db_session, str(reserved.id)) == 1


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"registration_attempt_id": str(uuid.uuid4())},
        {
            "registration_attempt_id": str(uuid.uuid4()),
            "reservation_token": generate_reservation_token(),
            "extra": True,
        },
        {
            "registration_attempt_id": str(uuid.uuid1()),
            "reservation_token": generate_reservation_token(),
        },
        {"registration_attempt_id": str(uuid.uuid4()), "reservation_token": "short"},
    ],
    ids=["empty", "no-token", "extra-field", "uuid-v1", "short-token"],
)
def test_release_rejects_invalid_payloads(
    api_client: TestClient,
    payload: dict[str, object],
) -> None:
    response = api_client.request("DELETE", f"{BASE}/{uuid.uuid4()}", json=payload)

    assert response.status_code == 422


def test_release_rejects_malformed_reservation_id(api_client: TestClient) -> None:
    response = release(
        api_client,
        "not-a-uuid",
        str(uuid.uuid4()),
        generate_reservation_token(),
    )

    assert response.status_code == 422


def test_release_returns_429_when_rate_limited(
    api_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def deny_request(buckets: list[object]) -> RateLimitResult:
        observed["buckets"] = buckets
        return RateLimitResult(allowed=False, retry_after_seconds=60)

    monkeypatch.setattr("app.api.v1.endpoints.auth.consume_rate_limit_buckets", deny_request)

    response = release(
        api_client,
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        generate_reservation_token(),
    )

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "60"
    buckets = observed["buckets"]
    assert isinstance(buckets, list)
    assert [(b.scope, b.kind, b.limit, b.window_seconds) for b in buckets] == [
        ("auth:username-reservations:release:ip", "ip", 20, 900)
    ]


def test_release_fails_closed_on_database_error(
    api_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_release(*_args: object) -> None:
        raise SQLAlchemyError("simulated database failure")

    monkeypatch.setattr("app.api.v1.endpoints.auth.release_username_reservation", fail_release)

    response = release(
        api_client,
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        generate_reservation_token(),
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable."}
