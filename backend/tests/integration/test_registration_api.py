from collections.abc import Generator
from types import SimpleNamespace

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.main import app
from app.models.user import User


@pytest.fixture
def api_client(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[TestClient]:
    """Use the isolated integration-test session for HTTP requests."""

    def override_db_session() -> Generator[Session]:
        yield db_session

    # Keep ordinary tests independent of terminal output.
    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.send_verification_email",
        lambda recipient_email, raw_token: None,
    )
    app.dependency_overrides[get_db_session] = override_db_session

    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db_session, None)


def test_register_endpoint_returns_safe_account_response(
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

    assert response.status_code == 201

    data = response.json()
    assert data["email"] == "httpuser@example.com"
    assert data["display_name"] == "HTTP User"
    assert data["is_active"] is True
    assert data["email_verified_at"] is None
    assert "id" in data
    assert "created_at" in data
    assert "password" not in data
    assert "password_hash" not in data


def test_register_delivers_token_without_exposing_it_in_response(
    api_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    delivered: dict[str, str] = {}

    def capture_delivery(recipient_email: str, raw_token: str) -> None:
        delivered["recipient_email"] = recipient_email
        delivered["raw_token"] = raw_token

    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.send_verification_email",
        capture_delivery,
    )

    response = api_client.post(
        "/api/v1/auth/register",
        json={
            "email": "delivery@example.com",
            "display_name": "Delivery Test",
            "password": "a-strong-test-password",
        },
    )

    assert response.status_code == 201
    assert delivered["recipient_email"] == "delivery@example.com"
    assert delivered["raw_token"]
    assert delivered["raw_token"] not in response.text
    assert "token" not in response.json()


def test_register_is_blocked_outside_development_and_testing(
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
            "email": "production-blocked@example.com",
            "display_name": "Production Blocked",
            "password": "a-strong-test-password",
        },
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Email verification delivery is not configured for this environment."
    }

    user = db_session.scalar(select(User).where(User.email == "production-blocked@example.com"))
    assert user is None


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

    assert first_response.status_code == 201
    assert second_response.status_code == 409
    assert second_response.json() == {
        "detail": "Unable to register with the supplied email address."
    }


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

    assert first_response.status_code == 201
    assert first_response.json()["email"] == "caseuser@example.com"
    assert second_response.status_code == 409


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

    assert response.status_code == 201

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
