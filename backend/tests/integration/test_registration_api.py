import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.main import app
from app.models.email_outbox import EmailOutbox
from app.models.user import User
from app.models.username_claim import UsernameClaim
from app.security.email_outbox_encryption import decrypt_email_payload
from app.security.passwords import hash_password
from app.security.username_reservations import generate_reservation_token
from app.services.username_reservations import create_username_reservation

REGISTER = "/api/v1/auth/register"

GENERIC_RESPONSE = {
    "message": (
        "If an account can be created with this email, a verification email will be sent shortly."
    )
}


@pytest.fixture
def api_client(
    db_session: Session,
    configured_outbox_encryption: None,
) -> Generator[TestClient]:
    """Use the isolated integration-test session for HTTP requests."""

    def override_db_session() -> Generator[Session]:
        yield db_session

    app.dependency_overrides[get_db_session] = override_db_session

    try:
        with TestClient(app, headers={"Origin": "http://localhost:5173"}) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db_session, None)


def reserve_username(db_session: Session) -> dict[str, str]:
    """Create a real reservation and end the session transaction before any request."""
    attempt_id = uuid.uuid4()
    username = f"u{uuid.uuid4().hex[:12]}"
    created = create_username_reservation(db_session, username, attempt_id)
    db_session.commit()
    return {
        "username": created.username,
        "reservation_id": str(created.reservation_id),
        "registration_attempt_id": str(attempt_id),
        "reservation_token": created.reservation_token,
    }


def registration_payload(
    db_session: Session,
    *,
    email: str,
    display_name: str = "Test User",
    password: str = "a-strong-test-password",
    **overrides: str,
) -> dict[str, str]:
    payload = {
        "email": email,
        "display_name": display_name,
        "password": password,
        **reserve_username(db_session),
    }
    payload.update(overrides)
    return payload


def get_claim(db_session: Session, username: str) -> UsernameClaim | None:
    return db_session.scalar(select(UsernameClaim).where(UsernameClaim.username == username))


def count_users(db_session: Session, email: str) -> int:
    return db_session.scalar(select(func.count()).select_from(User).where(User.email == email)) or 0


def test_register_endpoint_returns_generic_response(
    api_client: TestClient,
    db_session: Session,
) -> None:
    response = api_client.post(
        REGISTER,
        json=registration_payload(
            db_session,
            email="HttpUser@example.com",
            display_name="  HTTP User  ",
        ),
    )

    assert response.status_code == 202
    assert response.json() == GENERIC_RESPONSE


def test_register_consumes_the_reservation_as_a_permanent_username(
    api_client: TestClient,
    db_session: Session,
) -> None:
    payload = registration_payload(db_session, email="permanentapi@example.com")

    response = api_client.post(REGISTER, json=payload)

    assert response.status_code == 202
    user = db_session.scalar(select(User).where(User.email == "permanentapi@example.com"))
    assert user is not None
    claim = get_claim(db_session, payload["username"])
    assert claim is not None
    assert claim.claim_type == "permanent"
    assert claim.user_id == user.id
    assert claim.token_hash is None
    assert claim.expires_at is None
    assert user.username == payload["username"]


def test_register_queues_encrypted_token_without_exposing_it_in_response(
    api_client: TestClient,
    db_session: Session,
) -> None:
    response = api_client.post(
        REGISTER,
        json=registration_payload(
            db_session,
            email="delivery@example.com",
            display_name="Delivery Test",
        ),
    )

    assert response.status_code == 202
    assert response.json() == GENERIC_RESPONSE

    job = db_session.scalar(
        select(EmailOutbox).where(EmailOutbox.event_type == "email.verification")
    )
    assert job is not None
    assert job.status == "pending"
    assert job.encrypted_payload
    payload = decrypt_email_payload(job.event_type, job.encrypted_payload)

    assert payload["recipient"] == "delivery@example.com"
    assert payload["display_name"] == "Delivery Test"
    assert payload["verification_token"]
    assert payload["verification_token"] not in response.text
    assert "token" not in response.json()


def test_register_queues_email_in_production_environment(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = registration_payload(
        db_session,
        email="production@example.com",
        display_name="Production User",
    )
    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.get_settings",
        lambda: SimpleNamespace(environment="production"),
    )

    response = api_client.post(REGISTER, json=payload)

    assert response.status_code == 202

    user = db_session.scalar(select(User).where(User.email == "production@example.com"))
    assert user is not None

    job = db_session.scalar(
        select(EmailOutbox).where(EmailOutbox.event_type == "email.verification")
    )
    assert job is not None
    decrypted = decrypt_email_payload(job.event_type, job.encrypted_payload)
    assert decrypted["recipient"] == user.email
    assert decrypted["display_name"] == user.display_name


def test_register_endpoint_rejects_duplicate_email(
    api_client: TestClient,
    db_session: Session,
) -> None:
    first_payload = registration_payload(
        db_session,
        email="httpduplicate@example.com",
        display_name="HTTP Duplicate",
    )
    first_response = api_client.post(REGISTER, json=first_payload)

    second_payload = registration_payload(
        db_session,
        email="httpduplicate@example.com",
        display_name="HTTP Duplicate",
    )
    second_response = api_client.post(REGISTER, json=second_payload)

    assert first_response.status_code == 202
    assert second_response.status_code == 202
    assert first_response.json() == GENERIC_RESPONSE
    assert second_response.json() == GENERIC_RESPONSE
    assert count_users(db_session, "httpduplicate@example.com") == 1


RELEASE = "/api/v1/auth/username-reservations"


def _duplicate_email_second_payload(
    api_client: TestClient,
    db_session: Session,
    email: str,
) -> dict[str, object]:
    """Register an email, then submit a second registration that reuses it."""
    first = api_client.post(REGISTER, json=registration_payload(db_session, email=email))
    assert first.status_code == 202

    second_payload = registration_payload(db_session, email=email)
    second = api_client.post(REGISTER, json=second_payload)
    assert second.status_code == 202
    assert second.json() == GENERIC_RESPONSE

    return second_payload


def _release(api_client: TestClient, payload: dict[str, object]):
    return api_client.request(
        "DELETE",
        f"{RELEASE}/{payload['reservation_id']}",
        json={
            "registration_attempt_id": payload["registration_attempt_id"],
            "reservation_token": payload["reservation_token"],
        },
    )


def test_duplicate_email_burns_the_second_reservation_into_a_reserved_claim(
    api_client: TestClient,
    db_session: Session,
) -> None:
    second_payload = _duplicate_email_second_payload(api_client, db_session, "keepapi@example.com")

    claim = get_claim(db_session, second_payload["username"])
    assert claim is not None
    assert claim.claim_type == "reserved"
    assert claim.user_id is None
    assert claim.registration_attempt_id is None
    assert claim.token_hash is None
    assert claim.expires_at is None


def test_release_cannot_tell_a_duplicate_email_from_a_new_account(
    api_client: TestClient,
    db_session: Session,
) -> None:
    new_payload = registration_payload(db_session, email="oraclenew@example.com")
    assert api_client.post(REGISTER, json=new_payload).status_code == 202
    duplicate_payload = _duplicate_email_second_payload(
        api_client, db_session, "oracledup@example.com"
    )

    after_new = _release(api_client, new_payload)
    after_duplicate = _release(api_client, duplicate_payload)

    expected = {"detail": "USERNAME_RESERVATION_INVALID"}
    assert after_new.status_code == after_duplicate.status_code == 409
    assert after_new.json() == after_duplicate.json() == expected


def test_registering_again_with_a_burned_reservation_is_rejected(
    api_client: TestClient,
    db_session: Session,
) -> None:
    duplicate_payload = _duplicate_email_second_payload(
        api_client, db_session, "againdup@example.com"
    )

    response = api_client.post(
        REGISTER,
        json={**duplicate_payload, "email": "againprobe@example.com"},
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_RESERVATION_INVALID"}
    assert count_users(db_session, "againprobe@example.com") == 0


def test_burned_username_cannot_be_reserved_again(
    api_client: TestClient,
    db_session: Session,
) -> None:
    duplicate_payload = _duplicate_email_second_payload(
        api_client, db_session, "reserveagain@example.com"
    )

    response = api_client.post(
        RELEASE,
        json={
            "username": duplicate_payload["username"],
            "registration_attempt_id": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_UNAVAILABLE"}


def test_register_endpoint_rejects_email_case_variation(
    api_client: TestClient,
    db_session: Session,
) -> None:
    first_response = api_client.post(
        REGISTER,
        json=registration_payload(
            db_session,
            email="CaseUser@example.com",
            display_name="Case User",
        ),
    )
    second_response = api_client.post(
        REGISTER,
        json=registration_payload(
            db_session,
            email="caseuser@example.com",
            display_name="Another Case User",
            password="another-strong-password",
        ),
    )

    assert first_response.status_code == 202
    assert second_response.status_code == 202
    assert first_response.json() == second_response.json()


def test_register_endpoint_stores_a_password_hash(
    api_client: TestClient,
    db_session: Session,
) -> None:
    password = "a-strong-test-password"

    response = api_client.post(
        REGISTER,
        json=registration_payload(
            db_session,
            email="hashedpassword@example.com",
            display_name="Hashed Password",
            password=password,
        ),
    )

    assert response.status_code == 202

    user = db_session.scalar(select(User).where(User.email == "hashedpassword@example.com"))

    assert user is not None
    assert user.password_hash is not None
    assert user.password_hash != password
    assert user.password_hash.startswith("$argon2")
    assert PasswordHasher().verify(user.password_hash, password)


def test_register_endpoint_rejects_invalid_password(
    api_client: TestClient,
    db_session: Session,
) -> None:
    response = api_client.post(
        REGISTER,
        json=registration_payload(
            db_session,
            email="invalidpassword@example.com",
            display_name="Invalid Password",
            password="short",
        ),
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "field",
    ["username", "reservation_id", "registration_attempt_id", "reservation_token"],
)
def test_register_requires_every_reservation_field(
    api_client: TestClient,
    db_session: Session,
    field: str,
) -> None:
    payload = registration_payload(db_session, email=f"missing{field}@example.com")
    del payload[field]

    response = api_client.post(REGISTER, json=payload)

    assert response.status_code == 422
    assert count_users(db_session, f"missing{field}@example.com") == 0


def test_register_rejects_unexpected_fields(
    api_client: TestClient,
    db_session: Session,
) -> None:
    payload = registration_payload(db_session, email="extrafield@example.com")
    payload["unexpected"] = "value"

    response = api_client.post(REGISTER, json=payload)

    assert response.status_code == 422
    assert count_users(db_session, "extrafield@example.com") == 0


BAD_RESERVATION_OVERRIDES = {
    "wrong_token": lambda: {"reservation_token": generate_reservation_token()},
    "wrong_attempt_id": lambda: {"registration_attempt_id": str(uuid.uuid4())},
    "wrong_username": lambda: {"username": "different_name"},
    "unknown_reservation_id": lambda: {"reservation_id": str(uuid.uuid4())},
}


@pytest.mark.parametrize("case", list(BAD_RESERVATION_OVERRIDES))
def test_invalid_reservation_returns_409_and_creates_no_user(
    api_client: TestClient,
    db_session: Session,
    case: str,
) -> None:
    email = f"{case}api@example.com"
    valid = registration_payload(db_session, email=email)
    bad = {**valid, **BAD_RESERVATION_OVERRIDES[case]()}

    response = api_client.post(REGISTER, json=bad)

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_RESERVATION_INVALID"}
    assert email not in response.text
    assert count_users(db_session, email) == 0
    claim = get_claim(db_session, valid["username"])
    assert claim is not None
    assert claim.claim_type == "reservation"


def test_expired_reservation_returns_409_expired(
    api_client: TestClient,
    db_session: Session,
) -> None:
    payload = registration_payload(db_session, email="expiredapi@example.com")
    claim = get_claim(db_session, payload["username"])
    assert claim is not None
    claim.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()

    response = api_client.post(REGISTER, json=payload)

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_RESERVATION_EXPIRED"}
    assert count_users(db_session, "expiredapi@example.com") == 0


def test_expired_reservation_with_wrong_token_does_not_reveal_expiry(
    api_client: TestClient,
    db_session: Session,
) -> None:
    payload = registration_payload(db_session, email="hiddenexpiryapi@example.com")
    claim = get_claim(db_session, payload["username"])
    assert claim is not None
    claim.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()

    response = api_client.post(
        REGISTER,
        json={**payload, "reservation_token": generate_reservation_token()},
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "USERNAME_RESERVATION_INVALID"}


def test_consumed_reservation_cannot_be_reused(
    api_client: TestClient,
    db_session: Session,
) -> None:
    payload = registration_payload(db_session, email="reuse1@example.com")
    first = api_client.post(REGISTER, json=payload)
    second = api_client.post(REGISTER, json={**payload, "email": "reuse2@example.com"})

    assert first.status_code == 202
    assert second.status_code == 409
    assert second.json() == {"detail": "USERNAME_RESERVATION_INVALID"}
    assert count_users(db_session, "reuse2@example.com") == 0


def test_bad_reservation_returns_409_even_for_an_existing_email(
    api_client: TestClient,
    db_session: Session,
) -> None:
    first = api_client.post(
        REGISTER,
        json=registration_payload(db_session, email="existingapi@example.com"),
    )
    second_payload = registration_payload(
        db_session,
        email="existingapi@example.com",
        reservation_token=generate_reservation_token(),
    )

    second = api_client.post(REGISTER, json=second_payload)

    assert first.status_code == 202
    assert second.status_code == 409
    assert second.json() == {"detail": "USERNAME_RESERVATION_INVALID"}


def _record_registration_hashing(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every password hashed by the registration service."""
    hashed: list[str] = []

    def recording_hash_password(password: str) -> str:
        hashed.append(password)
        return hash_password(password)

    monkeypatch.setattr("app.services.registration.hash_password", recording_hash_password)
    return hashed


def test_register_hashes_password_for_new_email(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = registration_payload(db_session, email="newhash@example.com")
    hashed = _record_registration_hashing(monkeypatch)

    response = api_client.post(REGISTER, json=payload)

    assert response.status_code == 202
    assert hashed == ["a-strong-test-password"]


def test_register_hashes_password_for_duplicate_email(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A duplicate pays for Argon2 too so response timing does not reveal accounts."""
    first_payload = registration_payload(db_session, email="duplicatehash@example.com")
    first_response = api_client.post(REGISTER, json=first_payload)
    assert first_response.status_code == 202

    second_payload = registration_payload(db_session, email="duplicatehash@example.com")
    hashed = _record_registration_hashing(monkeypatch)

    second_response = api_client.post(REGISTER, json=second_payload)

    assert second_response.status_code == 202
    assert second_response.json() == first_response.json()
    assert hashed == [second_payload["password"]]
    users = db_session.scalars(select(User).where(User.email == "duplicatehash@example.com")).all()
    assert len(users) == 1
    jobs = db_session.scalars(select(EmailOutbox)).all()
    assert len(jobs) == 1


def test_register_hashes_password_before_rejecting_a_bad_reservation(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = registration_payload(
        db_session,
        email="hashfirst@example.com",
        reservation_token=generate_reservation_token(),
    )
    hashed = _record_registration_hashing(monkeypatch)

    response = api_client.post(REGISTER, json=payload)

    assert response.status_code == 409
    assert hashed == [payload["password"]]
