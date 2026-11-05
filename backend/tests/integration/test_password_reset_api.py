import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.password_reset import PASSWORD_RESET_EMAIL_EVENT
from app.db.session import get_db_session
from app.main import app
from app.models.email_outbox import EmailOutbox
from app.models.password_reset_token import PasswordResetToken
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.security.email_outbox_encryption import decrypt_email_payload
from app.security.passwords import hash_password, verify_password
from app.services.password_reset import (
    create_password_reset_token,
    hash_password_reset_token,
)
from app.services.refresh_sessions import create_refresh_session

OLD_PASSWORD = "Old-Password-12345!"
NEW_PASSWORD = "New-Password-98765!"
FORGOT_MESSAGE = "If an eligible account exists, a password reset email will be sent shortly."
RESET_MESSAGE = "Password reset successfully. Please log in with your new password."
INVALID_TOKEN = {"detail": "Invalid or expired reset token."}


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


def create_user(
    session: Session,
    *,
    active: bool = True,
    verified: bool = True,
    with_password: bool = True,
) -> User:
    """Create and commit a user so a request-level rollback keeps the setup."""
    user = User(
        email=f"{uuid.uuid4().hex}@example.com",
        display_name="Password Reset API Test",
        password_hash=hash_password(OLD_PASSWORD) if with_password else None,
        is_active=active,
        email_verified_at=datetime.now(UTC) if verified else None,
    )
    session.add(user)
    session.flush()
    session.commit()
    return user


def issue_token(session: Session, user_id: uuid.UUID) -> str:
    raw_token = create_password_reset_token(session, user_id)
    session.commit()
    return raw_token


def outbox_count(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(EmailOutbox)) or 0


def token_count(session: Session, user_id: uuid.UUID) -> int:
    return (
        session.scalar(
            select(func.count())
            .select_from(PasswordResetToken)
            .where(PasswordResetToken.user_id == user_id)
        )
        or 0
    )


def get_token_record(session: Session, raw_token: str) -> PasswordResetToken:
    record = session.scalar(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == hash_password_reset_token(raw_token)
        )
    )
    assert record is not None
    return record


# ---------------------------------------------------------------- forgot-password


def test_forgot_password_queues_encrypted_email_for_eligible_account(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = create_user(db_session)
    user_id = user.id
    email = user.email

    response = api_client.post("/api/v1/auth/forgot-password", json={"email": email})

    assert response.status_code == 202
    assert response.json() == {"message": FORGOT_MESSAGE}

    job = db_session.scalar(
        select(EmailOutbox).where(EmailOutbox.event_type == PASSWORD_RESET_EMAIL_EVENT)
    )
    assert job is not None
    assert job.encrypted_payload is not None
    payload = decrypt_email_payload(job.event_type, job.encrypted_payload)
    assert payload["recipient"] == email
    assert payload["display_name"] == "Password Reset API Test"
    raw_token = payload["password_reset_token"]
    assert isinstance(raw_token, str) and raw_token

    # The raw token must never be exposed to the HTTP caller.
    assert raw_token not in response.text
    assert "token" not in response.json()

    record = get_token_record(db_session, raw_token)
    assert record.user_id == user_id
    assert record.used_at is None
    assert record.expires_at > datetime.now(UTC)


def test_forgot_password_normalizes_email_case(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = create_user(db_session)

    response = api_client.post(
        "/api/v1/auth/forgot-password",
        json={"email": user.email.upper()},
    )

    assert response.status_code == 202
    assert outbox_count(db_session) == 1


def test_forgot_password_unknown_email_returns_generic_response(
    api_client: TestClient,
    db_session: Session,
) -> None:
    response = api_client.post(
        "/api/v1/auth/forgot-password",
        json={"email": "unknown@example.com"},
    )

    assert response.status_code == 202
    assert response.json() == {"message": FORGOT_MESSAGE}
    assert outbox_count(db_session) == 0


@pytest.mark.parametrize(
    ("active", "verified", "with_password"),
    [
        (False, True, True),
        (True, False, True),
        (True, True, False),
    ],
    ids=["inactive", "unverified", "passwordless"],
)
def test_forgot_password_ineligible_account_returns_generic_response(
    api_client: TestClient,
    db_session: Session,
    active: bool,
    verified: bool,
    with_password: bool,
) -> None:
    user = create_user(
        db_session,
        active=active,
        verified=verified,
        with_password=with_password,
    )
    user_id = user.id

    response = api_client.post("/api/v1/auth/forgot-password", json={"email": user.email})

    assert response.status_code == 202
    assert response.json() == {"message": FORGOT_MESSAGE}
    assert outbox_count(db_session) == 0
    assert token_count(db_session, user_id) == 0


def test_forgot_password_cooldown_returns_generic_response(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = create_user(db_session)
    user_id = user.id
    issue_token(db_session, user_id)

    response = api_client.post("/api/v1/auth/forgot-password", json={"email": user.email})

    assert response.status_code == 202
    assert response.json() == {"message": FORGOT_MESSAGE}
    assert outbox_count(db_session) == 0
    assert token_count(db_session, user_id) == 1


def test_forgot_password_enqueue_failure_rolls_back_token_creation(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = create_user(db_session)
    user_id = user.id
    email = user.email

    def fail_enqueue(*args: object, **kwargs: object) -> None:
        raise RuntimeError("simulated outbox failure")

    monkeypatch.setattr("app.api.v1.endpoints.auth.enqueue_email", fail_enqueue)

    with pytest.raises(RuntimeError):
        api_client.post("/api/v1/auth/forgot-password", json={"email": email})

    assert token_count(db_session, user_id) == 0
    assert outbox_count(db_session) == 0


@pytest.mark.parametrize(
    "payload",
    [{}, {"email": ""}, {"email": "not-an-email"}, {"email": None}],
    ids=["missing", "empty", "malformed", "null"],
)
def test_forgot_password_rejects_invalid_payload(
    api_client: TestClient,
    db_session: Session,
    payload: dict[str, object],
) -> None:
    response = api_client.post("/api/v1/auth/forgot-password", json=payload)

    assert response.status_code == 422
    assert outbox_count(db_session) == 0


# ---------------------------------------------------------------- reset-password


def test_reset_password_changes_password_without_authentication(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = create_user(db_session)
    raw_token = issue_token(db_session, user.id)

    # No Authorization header and no session cookies are sent.
    assert "authorization" not in {name.lower() for name in api_client.headers}

    response = api_client.post(
        "/api/v1/auth/reset-password",
        json={"token": raw_token, "new_password": NEW_PASSWORD},
    )

    assert response.status_code == 200
    assert response.json() == {"message": RESET_MESSAGE}
    assert "set-cookie" not in response.headers
    assert raw_token not in response.text
    assert NEW_PASSWORD not in response.text

    db_session.refresh(user)
    assert user.password_hash is not None
    assert verify_password(NEW_PASSWORD, user.password_hash)
    assert not verify_password(OLD_PASSWORD, user.password_hash)

    record = get_token_record(db_session, raw_token)
    assert record.used_at is not None


def test_reset_token_is_single_use(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = create_user(db_session)
    raw_token = issue_token(db_session, user.id)

    first = api_client.post(
        "/api/v1/auth/reset-password",
        json={"token": raw_token, "new_password": NEW_PASSWORD},
    )
    second = api_client.post(
        "/api/v1/auth/reset-password",
        json={"token": raw_token, "new_password": "Another-Password-5555!"},
    )

    assert first.status_code == 200
    assert second.status_code == 400
    assert second.json() == INVALID_TOKEN

    db_session.refresh(user)
    assert user.password_hash is not None
    assert verify_password(NEW_PASSWORD, user.password_hash)


def test_reset_password_revokes_all_active_sessions_of_the_user_only(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = create_user(db_session)
    other_user = create_user(db_session)
    user_id = user.id
    other_id = other_user.id

    create_refresh_session(db_session, user_id)
    create_refresh_session(db_session, user_id)
    create_refresh_session(db_session, other_id)
    raw_token = issue_token(db_session, user_id)

    response = api_client.post(
        "/api/v1/auth/reset-password",
        json={"token": raw_token, "new_password": NEW_PASSWORD},
    )
    assert response.status_code == 200

    own_sessions = db_session.scalars(
        select(RefreshSession)
        .where(RefreshSession.user_id == user_id)
        .execution_options(populate_existing=True)
    ).all()
    assert len(own_sessions) == 2
    assert all(record.revoked_at is not None for record in own_sessions)

    other_sessions = db_session.scalars(
        select(RefreshSession)
        .where(RefreshSession.user_id == other_id)
        .execution_options(populate_existing=True)
    ).all()
    assert len(other_sessions) == 1
    assert other_sessions[0].revoked_at is None


def test_reset_password_rejects_expired_token_and_keeps_old_password(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = create_user(db_session)
    raw_token = issue_token(db_session, user.id)

    record = get_token_record(db_session, raw_token)
    record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.flush()
    db_session.commit()

    response = api_client.post(
        "/api/v1/auth/reset-password",
        json={"token": raw_token, "new_password": NEW_PASSWORD},
    )

    assert response.status_code == 400
    assert response.json() == INVALID_TOKEN

    db_session.refresh(user)
    assert user.password_hash is not None
    assert verify_password(OLD_PASSWORD, user.password_hash)
    assert not verify_password(NEW_PASSWORD, user.password_hash)


def test_reset_password_rejects_unknown_token_and_keeps_old_password(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user = create_user(db_session)
    create_refresh_session(db_session, user.id)
    db_session.commit()

    response = api_client.post(
        "/api/v1/auth/reset-password",
        json={"token": "unknown-reset-token", "new_password": NEW_PASSWORD},
    )

    assert response.status_code == 400
    assert response.json() == INVALID_TOKEN

    db_session.refresh(user)
    assert user.password_hash is not None
    assert verify_password(OLD_PASSWORD, user.password_hash)

    sessions = db_session.scalars(
        select(RefreshSession)
        .where(RefreshSession.user_id == user.id)
        .execution_options(populate_existing=True)
    ).all()
    assert all(record.revoked_at is None for record in sessions)


@pytest.mark.parametrize("token", [" ", "\n", "\t "])
def test_reset_password_rejects_blank_token(
    api_client: TestClient,
    token: str,
) -> None:
    response = api_client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": NEW_PASSWORD},
    )

    assert response.status_code == 400
    assert response.json() == INVALID_TOKEN


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"token": "abc"},
        {"new_password": NEW_PASSWORD},
        {"token": "", "new_password": NEW_PASSWORD},
        {"token": "x" * 257, "new_password": NEW_PASSWORD},
        {"token": None, "new_password": NEW_PASSWORD},
    ],
    ids=["empty", "no-password", "no-token", "empty-token", "oversized-token", "null-token"],
)
def test_reset_password_rejects_malformed_payload(
    api_client: TestClient,
    payload: dict[str, object],
) -> None:
    response = api_client.post("/api/v1/auth/reset-password", json=payload)

    assert response.status_code == 422


@pytest.mark.parametrize("new_password", ["short", "x" * 129])
def test_reset_password_rejects_invalid_new_password_without_using_token(
    api_client: TestClient,
    db_session: Session,
    new_password: str,
) -> None:
    user = create_user(db_session)
    raw_token = issue_token(db_session, user.id)

    response = api_client.post(
        "/api/v1/auth/reset-password",
        json={"token": raw_token, "new_password": new_password},
    )

    assert response.status_code == 422

    record = get_token_record(db_session, raw_token)
    assert record.used_at is None
    db_session.refresh(user)
    assert user.password_hash is not None
    assert verify_password(OLD_PASSWORD, user.password_hash)
