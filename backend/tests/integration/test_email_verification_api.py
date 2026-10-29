import hashlib
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.main import app
from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User
from app.services.email_verification import create_verification_token


@pytest.fixture
def api_client(db_session: Session) -> Generator[TestClient]:
    """Use the isolated integration-test session for HTTP requests."""

    def override_db_session() -> Generator[Session]:
        yield db_session

    app.dependency_overrides[get_db_session] = override_db_session

    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db_session, None)


def create_unverified_user(session: Session) -> User:
    """Create an unverified user for endpoint tests."""

    user = User(
        email=f"{uuid.uuid4().hex}@example.com",
        display_name="API Verification Test",
        password_hash=None,
        email_verified_at=None,
    )
    session.add(user)
    session.flush()
    return user


def test_verify_email_endpoint_verifies_user(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = create_unverified_user(db_session)
    raw_token = create_verification_token(db_session, user.id)
    user_id = user.id

    response = api_client.post(
        "/api/v1/auth/verify-email",
        json={"token": raw_token},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Email verified successfully."
    assert data["email_verified_at"] is not None
    assert "token" not in data
    assert "token_hash" not in data
    assert "password_hash" not in data

    db_session.refresh(user)
    assert user.id == user_id
    assert user.email_verified_at is not None

    record = db_session.scalar(
        select(EmailVerificationToken).where(EmailVerificationToken.user_id == user_id)
    )
    assert record is not None
    assert record.used_at is not None


def test_verify_email_endpoint_rejects_unknown_token(
    api_client: TestClient,
) -> None:
    response = api_client.post(
        "/api/v1/auth/verify-email",
        json={"token": "unknown-token"},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid or expired verification token."}


@pytest.mark.parametrize("token", ["", " ", "\n"])
def test_verify_email_endpoint_rejects_blank_token(
    api_client: TestClient,
    token: str,
) -> None:
    response = api_client.post(
        "/api/v1/auth/verify-email",
        json={"token": token},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid or expired verification token."}


def test_verify_email_endpoint_rejects_expired_token(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = create_unverified_user(db_session)
    user_id = user.id
    raw_token = create_verification_token(db_session, user_id)

    record = db_session.scalar(
        select(EmailVerificationToken).where(EmailVerificationToken.user_id == user_id)
    )
    assert record is not None

    record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.flush()

    # Isolate setup from the request's rollback behaviour.
    db_session.commit()

    response = api_client.post(
        "/api/v1/auth/verify-email",
        json={"token": raw_token},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid or expired verification token."}

    restored_user = db_session.scalar(select(User).where(User.id == user_id))
    assert restored_user is not None
    assert restored_user.email_verified_at is None


def test_verify_email_endpoint_rejects_token_reuse(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = create_unverified_user(db_session)
    raw_token = create_verification_token(db_session, user.id)

    first_response = api_client.post(
        "/api/v1/auth/verify-email",
        json={"token": raw_token},
    )
    second_response = api_client.post(
        "/api/v1/auth/verify-email",
        json={"token": raw_token},
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 400
    assert second_response.json() == {"detail": "Invalid or expired verification token."}


def test_verify_email_endpoint_requires_token_field(
    api_client: TestClient,
) -> None:
    response = api_client.post(
        "/api/v1/auth/verify-email",
        json={},
    )

    assert response.status_code == 422


RESEND_VERIFICATION_MESSAGE = (
    "If an eligible account exists, a verification email will be sent shortly."
)


def test_resend_verification_creates_replacement_token(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = create_unverified_user(db_session)
    old_raw_token = create_verification_token(db_session, user.id)

    old_record = db_session.scalar(
        select(EmailVerificationToken).where(
            EmailVerificationToken.token_hash == hashlib.sha256(old_raw_token.encode()).hexdigest()
        )
    )
    assert old_record is not None

    # simulate a token created more than 120 seconds ago.
    old_record.created_at = datetime.now(UTC) - timedelta(minutes=3)
    db_session.flush()

    sent_emails: list[tuple[str, str]] = []

    def capture_email(recipient_email: str, raw_token: str) -> None:
        sent_emails.append((recipient_email, raw_token))

    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.send_verification_email",
        capture_email,
    )

    response = api_client.post(
        "/api/v1/auth/resend-verification",
        json={"email": user.email},
    )

    assert response.status_code == 200
    assert response.json() == {"message": RESEND_VERIFICATION_MESSAGE}
    assert len(sent_emails) == 1
    assert sent_emails[0][0] == user.email

    old_record = db_session.scalar(
        select(EmailVerificationToken).where(
            EmailVerificationToken.token_hash == hashlib.sha256(old_raw_token.encode()).hexdigest()
        )
    )
    new_record = db_session.scalar(
        select(EmailVerificationToken).where(
            EmailVerificationToken.token_hash
            == hashlib.sha256(sent_emails[0][1].encode()).hexdigest()
        )
    )

    assert old_record is not None
    assert old_record.expires_at <= datetime.now(UTC)

    assert new_record is not None
    assert new_record.user_id == user.id
    assert new_record.used_at is None
    assert new_record.expires_at > datetime.now(UTC)


def test_resend_verification_unknown_email_returns_generic_response(
    api_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_emails: list[tuple[str, str]] = []

    def capture_email(recipient_email: str, raw_token: str) -> None:
        sent_emails.append((recipient_email, raw_token))

    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.send_verification_email",
        capture_email,
    )

    response = api_client.post(
        "/api/v1/auth/resend-verification",
        json={"email": "unknown@example.com"},
    )

    assert response.status_code == 200
    assert response.json() == {"message": RESEND_VERIFICATION_MESSAGE}
    assert sent_emails == []


def test_resend_verification_verified_account_returns_generic_response(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = create_unverified_user(db_session)
    user.email_verified_at = datetime.now(UTC)
    db_session.flush()

    sent_emails: list[tuple[str, str]] = []

    def capture_email(recipient_email: str, raw_token: str) -> None:
        sent_emails.append((recipient_email, raw_token))

    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.send_verification_email",
        capture_email,
    )

    response = api_client.post(
        "/api/v1/auth/resend-verification",
        json={"email": user.email},
    )

    assert response.status_code == 200
    assert response.json() == {"message": RESEND_VERIFICATION_MESSAGE}
    assert sent_emails == []


def test_resend_verification_cooldown_returns_generic_response(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = create_unverified_user(db_session)
    create_verification_token(db_session, user.id)

    sent_emails: list[tuple[str, str]] = []

    def capture_email(recipient_email: str, raw_token: str) -> None:
        sent_emails.append((recipient_email, raw_token))

    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.send_verification_email",
        capture_email,
    )

    response = api_client.post(
        "/api/v1/auth/resend-verification",
        json={"email": user.email},
    )

    assert response.status_code == 200
    assert response.json() == {"message": RESEND_VERIFICATION_MESSAGE}
    assert sent_emails == []
