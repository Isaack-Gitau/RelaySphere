import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User
from app.schemas.auth import RegisterRequest
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


def test_registration_workflow_creates_user_and_verification_token(
    db_session: Session,
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

    record = db_session.scalar(
        select(EmailVerificationToken).where(EmailVerificationToken.user_id == user.id)
    )

    assert user.email == "verifiedflow@example.com"
    assert user.email_verified_at is None
    assert record is not None
    assert record.token_hash != raw_token

    from app.services.email_verification import hash_verification_token

    assert record.token_hash == hash_verification_token(raw_token)


def test_registration_workflow_rolls_back_user_if_token_creation_fails(
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

    user = db_session.scalar(select(User).where(User.email == "tokenfailure@example.com"))
    assert user is None

    token = db_session.scalar(
        select(EmailVerificationToken).where(EmailVerificationToken.token_hash == "0" * 64)
    )
    assert token is None
