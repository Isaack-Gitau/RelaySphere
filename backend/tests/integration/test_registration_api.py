from collections.abc import Generator
from types import SimpleNamespace

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.main import app
from app.models.email_outbox import EmailOutbox
from app.models.user import User
from app.security.email_outbox_encryption import decrypt_email_payload
from app.security.passwords import hash_password


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


def test_register_endpoint_returns_generic_response(
    api_client: TestClient,
) -> None:
    response = api_client.post(
        "/api/v1/auth/register",
        json={
            "email": "HttpUser@example.com",
            "display_name": "  HTTP User  ",
            "password": "a-strong-test-password",
        },
    )

    assert response.status_code == 202
    assert response.json() == {
        "message": (
            "If an account can be created with this email, "
            "a verification email will be sent shortly."
        )
    }


def test_register_queues_encrypted_token_without_exposing_it_in_response(
    api_client: TestClient,
    db_session: Session,
) -> None:
    response = api_client.post(
        "/api/v1/auth/register",
        json={
            "email": "delivery@example.com",
            "display_name": "Delivery Test",
            "password": "a-strong-test-password",
        },
    )

    assert response.status_code == 202
    assert response.json() == {
        "message": (
            "If an account can be created with this email, "
            "a verification email will be sent shortly."
        )
    }

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
    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.get_settings",
        lambda: SimpleNamespace(environment="production"),
    )

    response = api_client.post(
        "/api/v1/auth/register",
        json={
            "email": "production@example.com",
            "display_name": "Production User",
            "password": "a-strong-test-password",
        },
    )

    assert response.status_code == 202

    user = db_session.scalar(select(User).where(User.email == "production@example.com"))
    assert user is not None

    job = db_session.scalar(
        select(EmailOutbox).where(EmailOutbox.event_type == "email.verification")
    )
    assert job is not None
    payload = decrypt_email_payload(job.event_type, job.encrypted_payload)
    assert payload["recipient"] == user.email
    assert payload["display_name"] == user.display_name


def test_register_endpoint_rejects_duplicate_email(
    api_client: TestClient,
) -> None:
    payload = {
        "email": "httpduplicate@example.com",
        "display_name": "HTTP Duplicate",
        "password": "a-strong-test-password",
    }

    first_response = api_client.post(
        "/api/v1/auth/register",
        json=payload,
    )
    second_response = api_client.post(
        "/api/v1/auth/register",
        json=payload,
    )

    expected_response = {
        "message": (
            "If an account can be created with this email, "
            "a verification email will be sent shortly."
        )
    }

    assert first_response.status_code == 202
    assert second_response.status_code == 202
    assert first_response.json() == expected_response
    assert second_response.json() == expected_response


def test_register_endpoint_rejects_email_case_variation(
    api_client: TestClient,
) -> None:
    first_response = api_client.post(
        "/api/v1/auth/register",
        json={
            "email": "CaseUser@example.com",
            "display_name": "Case User",
            "password": "a-strong-test-password",
        },
    )
    second_response = api_client.post(
        "/api/v1/auth/register",
        json={
            "email": "caseuser@example.com",
            "display_name": "Another Case User",
            "password": "another-strong-password",
        },
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
        "/api/v1/auth/register",
        json={
            "email": "hashedpassword@example.com",
            "display_name": "Hashed Password",
            "password": password,
        },
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
) -> None:
    response = api_client.post(
        "/api/v1/auth/register",
        json={
            "email": "invalidpassword@example.com",
            "display_name": "Invalid Password",
            "password": "short",
        },
    )

    assert response.status_code == 422


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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hashed = _record_registration_hashing(monkeypatch)

    response = api_client.post(
        "/api/v1/auth/register",
        json={
            "email": "newhash@example.com",
            "display_name": "New Hash",
            "password": "a-strong-test-password",
        },
    )

    assert response.status_code == 202
    assert hashed == ["a-strong-test-password"]


def test_register_hashes_password_for_duplicate_email(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A duplicate pays for Argon2 too so response timing does not reveal accounts."""
    payload = {
        "email": "duplicatehash@example.com",
        "display_name": "Duplicate Hash",
        "password": "a-strong-test-password",
    }
    first_response = api_client.post("/api/v1/auth/register", json=payload)
    assert first_response.status_code == 202

    hashed = _record_registration_hashing(monkeypatch)

    second_response = api_client.post("/api/v1/auth/register", json=payload)

    assert second_response.status_code == 202
    assert second_response.json() == first_response.json()
    assert hashed == [payload["password"]]
    users = db_session.scalars(select(User).where(User.email == payload["email"])).all()
    assert len(users) == 1
    jobs = db_session.scalars(select(EmailOutbox)).all()
    assert len(jobs) == 1
