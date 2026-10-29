import hashlib
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User
from app.services.email_verification import (
    TOKEN_EXPIRY_MINUTES,
    create_verification_token,
    hash_verification_token,
)


def create_test_user(session: Session) -> User:
    """Create a user for email verification tests."""
    user = User(
        email=f"{uuid.uuid4().hex}@example.com",
        display_name="Verification Test",
        password_hash=None,
        email_verified_at=None,
    )
    session.add(user)
    session.flush()
    return user


def test_create_verification_token_returns_secure_raw_token(
    db_session: Session,
) -> None:
    user = create_test_user(db_session)

    raw_token = create_verification_token(db_session, user.id)

    assert isinstance(raw_token, str)
    assert len(raw_token) >= 40


def test_verification_token_stores_only_sha256_hash(
    db_session: Session,
) -> None:
    user = create_test_user(db_session)

    raw_token = create_verification_token(db_session, user.id)

    record = db_session.scalar(
        select(EmailVerificationToken).where(EmailVerificationToken.user_id == user.id)
    )

    assert record is not None
    assert record.token_hash == hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    assert record.token_hash == hash_verification_token(raw_token)
    assert record.token_hash != raw_token
    assert len(record.token_hash) == 64


def test_verification_token_expires_after_configured_period(
    db_session: Session,
) -> None:
    user = create_test_user(db_session)
    before_creation = datetime.now(UTC)

    create_verification_token(db_session, user.id)

    record = db_session.scalar(
        select(EmailVerificationToken).where(EmailVerificationToken.user_id == user.id)
    )

    after_creation = datetime.now(UTC)

    assert record is not None
    assert record.expires_at >= before_creation + timedelta(minutes=TOKEN_EXPIRY_MINUTES)
    assert record.expires_at <= after_creation + timedelta(minutes=TOKEN_EXPIRY_MINUTES)
    assert record.used_at is None


def test_verification_token_is_not_committed_by_service(
    db_session: Session,
) -> None:
    user = create_test_user(db_session)

    create_verification_token(db_session, user.id)

    # The fixture binds the session to a Connection. Get its Engine
    # and use a separate connection to check transaction visibility.
    engine = db_session.get_bind().engine
    with engine.connect() as connection:
        count = connection.scalar(
            select(EmailVerificationToken.id).where(EmailVerificationToken.user_id == user.id)
        )

    assert count is None


def test_rolling_back_caller_transaction_removes_verification_token(
    db_session: Session,
) -> None:
    user = create_test_user(db_session)
    user_id = user.id

    create_verification_token(db_session, user_id)

    record_before_rollback = db_session.scalar(
        select(EmailVerificationToken).where(EmailVerificationToken.user_id == user_id)
    )
    assert record_before_rollback is not None

    db_session.rollback()

    record_after_rollback = db_session.scalar(
        select(EmailVerificationToken).where(EmailVerificationToken.user_id == user_id)
    )
    assert record_after_rollback is None
