import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.email_outbox import EmailOutbox
from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User
from app.schemas.auth import RegisterRequest
from app.security.email_outbox_encryption import decrypt_email_payload
from app.security.passwords import verify_password
from app.services import registration as registration_service
from app.services.registration import (
    EmailAlreadyRegisteredError,
    register_user,
    register_user_with_verification_token,
)


def test_register_user_creates_unverified_account(
    db_session: Session,
) -> None:
    registration = RegisterRequest(
        email="newuser@example.com",
        display_name="New User",
        password="a-strong-test-password",
    )

    user = register_user(db_session, registration)

    assert isinstance(user.id, uuid.UUID)
    assert user.email == "newuser@example.com"
    assert user.display_name == "New User"
    assert user.is_active is True
    assert user.email_verified_at is None
    assert user.password_hash is not None
    assert user.password_hash != registration.password
    assert verify_password(registration.password, user.password_hash)

    stored_user = db_session.scalar(select(User).where(User.email == "newuser@example.com"))
    assert stored_user is not None
    assert stored_user.id == user.id


def test_register_user_rejects_duplicate_email(
    db_session: Session,
) -> None:
    registration = RegisterRequest(
        email="duplicate@example.com",
        display_name="First User",
        password="a-strong-test-password",
    )
    original_user = register_user(db_session, registration)

    duplicate_registration = RegisterRequest(
        email="duplicate@example.com",
        display_name="Second User",
        password="another-strong-password",
    )

    with pytest.raises(EmailAlreadyRegisteredError):
        register_user(db_session, duplicate_registration)

    users = db_session.scalars(select(User).where(User.email == "duplicate@example.com")).all()

    assert len(users) == 1
    assert users[0].id == original_user.id
    assert users[0].display_name == "First User"


def test_register_user_normalizes_email(
    db_session: Session,
) -> None:
    registration = RegisterRequest(
        email="  MixedCase@example.com  ",
        display_name="Mixed Case",
        password="a-strong-test-password",
    )

    user = register_user(db_session, registration)

    assert user.email == "mixedcase@example.com"


def test_registration_workflow_creates_user_token_and_encrypted_email(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    registration = RegisterRequest(
        email="verifiedflow@example.com",
        display_name="Verification Flow",
        password="a-strong-test-password",
    )

    user, raw_token = register_user_with_verification_token(
        db_session,
        registration,
    )

    token_record = db_session.scalar(
        select(EmailVerificationToken).where(EmailVerificationToken.user_id == user.id)
    )
    outbox_record = db_session.scalar(
        select(EmailOutbox).where(EmailOutbox.event_type == "email.verification")
    )

    assert user.email == "verifiedflow@example.com"
    assert user.email_verified_at is None
    assert token_record is not None
    assert outbox_record is not None
    assert outbox_record.status == "pending"
    assert token_record.token_hash != raw_token

    from app.services.email_verification import hash_verification_token

    assert token_record.token_hash == hash_verification_token(raw_token)

    payload = decrypt_email_payload(
        outbox_record.event_type,
        outbox_record.encrypted_payload,
    )
    assert payload == {
        "recipient": user.email,
        "display_name": user.display_name,
        "verification_token": raw_token,
    }
    assert raw_token.encode("utf-8") not in outbox_record.encrypted_payload
    assert db_session.in_transaction()


def test_registration_workflow_leaves_rollback_to_caller_when_token_creation_fails(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = RegisterRequest(
        email="tokenfailure@example.com",
        display_name="Token Failure",
        password="a-strong-test-password",
    )

    def fail_token_creation(
        session: Session,
        user_id: uuid.UUID,
    ) -> str:
        raise RuntimeError("Simulated token creation failure")

    monkeypatch.setattr(
        registration_service,
        "create_verification_token",
        fail_token_creation,
    )

    with pytest.raises(RuntimeError, match="Simulated token creation failure"):
        register_user_with_verification_token(db_session, registration)

    # The service does not own the outer transaction.
    db_session.rollback()

    user = db_session.scalar(select(User).where(User.email == "tokenfailure@example.com"))
    assert user is None

    tokens = db_session.scalars(
        select(EmailVerificationToken)
        .join(User, EmailVerificationToken.user_id == User.id)
        .where(User.email == "tokenfailure@example.com")
    ).all()
    assert tokens == []

    outbox_records = db_session.scalars(
        select(EmailOutbox).where(EmailOutbox.event_type == "email.verification")
    ).all()
    assert outbox_records == []


def test_registration_workflow_is_atomic_when_email_enqueue_fails(
    db_session: Session,
    configured_outbox_encryption: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = RegisterRequest(
        email="enqueuefailure@example.com",
        display_name="Enqueue Failure",
        password="a-strong-test-password",
    )

    def fail_enqueue(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Simulated email enqueue failure")

    monkeypatch.setattr(registration_service, "enqueue_email", fail_enqueue)

    with pytest.raises(RuntimeError, match="Simulated email enqueue failure"):
        register_user_with_verification_token(db_session, registration)

    db_session.rollback()

    user = db_session.scalar(select(User).where(User.email == "enqueuefailure@example.com"))
    assert user is None

    tokens = db_session.scalars(
        select(EmailVerificationToken)
        .join(User, EmailVerificationToken.user_id == User.id)
        .where(User.email == "enqueuefailure@example.com")
    ).all()
    assert tokens == []

    outbox_records = db_session.scalars(
        select(EmailOutbox).where(EmailOutbox.event_type == "email.verification")
    ).all()
    assert outbox_records == []
