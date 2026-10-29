import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User
from app.services.email_verification import (
    EmailVerificationError,
    create_verification_token,
    verify_email_token,
)


def create_test_user(session: Session) -> User:
    """Create an unverified user for verification tests."""
    user = User(
        email=f"{uuid.uuid4().hex}@example.com",
        display_name="Verification Test",
        password_hash=None,
        email_verified_at=None,
    )
    session.add(user)
    session.flush()
    return user


def test_verify_email_token_marks_user_verified(
    db_session: Session,
) -> None:
    user = create_test_user(db_session)
    raw_token = create_verification_token(db_session, user.id)

    verified_user = verify_email_token(db_session, raw_token)

    record = db_session.scalar(
        select(EmailVerificationToken).where(EmailVerificationToken.user_id == user.id)
    )

    assert verified_user.id == user.id
    assert verified_user.email_verified_at is not None
    assert record is not None
    assert record.used_at is not None


def test_verify_email_token_rejects_unknown_token(
    db_session: Session,
) -> None:
    with pytest.raises(EmailVerificationError, match="Invalid or expired"):
        verify_email_token(db_session, "not-a-valid-token")


def test_verify_email_token_rejects_blank_token(
    db_session: Session,
) -> None:
    for raw_token in ("", " ", "\n"):
        with pytest.raises(EmailVerificationError):
            verify_email_token(db_session, raw_token)


def test_verify_email_token_rejects_expired_token(
    db_session: Session,
) -> None:
    user = create_test_user(db_session)
    raw_token = create_verification_token(db_session, user.id)

    record = db_session.scalar(
        select(EmailVerificationToken).where(EmailVerificationToken.user_id == user.id)
    )
    assert record is not None

    record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.flush()

    with pytest.raises(EmailVerificationError, match="Invalid or expired"):
        verify_email_token(db_session, raw_token)


def test_verify_email_token_rejects_reuse(
    db_session: Session,
) -> None:
    user = create_test_user(db_session)
    raw_token = create_verification_token(db_session, user.id)

    verify_email_token(db_session, raw_token)

    with pytest.raises(EmailVerificationError, match="Invalid or expired"):
        verify_email_token(db_session, raw_token)


def test_verification_changes_can_be_rolled_back(
    db_session: Session,
) -> None:
    user = create_test_user(db_session)
    user_id = user.id
    raw_token = create_verification_token(db_session, user_id)

    db_session.commit()

    verify_email_token(db_session, raw_token)
    db_session.rollback()

    restored_user = db_session.scalar(select(User).where(User.id == user_id))
    record = db_session.scalar(
        select(EmailVerificationToken).where(EmailVerificationToken.user_id == user_id)
    )

    assert restored_user is not None
    assert restored_user.email_verified_at is None
    assert record is not None
    assert record.used_at is None
