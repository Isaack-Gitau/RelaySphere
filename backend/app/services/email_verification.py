import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User

TOKEN_EXPIRY_MINUTES = 30


class EmailVerificationError(Exception):
    """Indicate that an email verification token cannot be used."""


def hash_verification_token(token: str) -> str:
    """Return a SHA-256 hash of a verification token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_verification_token(
    session: Session,
    user_id: uuid.UUID,
) -> str:
    """Create a secure verification token within the caller's transaction."""
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_verification_token(raw_token)
    expires_at = datetime.now(UTC) + timedelta(minutes=TOKEN_EXPIRY_MINUTES)

    record = EmailVerificationToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )

    session.add(record)
    session.flush()

    return raw_token


def verify_email_token(
    session: Session,
    raw_token: str,
) -> User:
    """Verify a user's email using a valid, unused verification token."""
    if not isinstance(raw_token, str) or not raw_token.strip():
        raise EmailVerificationError("Invalid or expired verification token.")

    token_hash = hash_verification_token(raw_token)

    record = session.scalar(
        select(EmailVerificationToken)
        .where(EmailVerificationToken.token_hash == token_hash)
        .with_for_update()
    )

    now = datetime.now(UTC)

    if record is None or record.used_at is not None or record.expires_at <= now:
        raise EmailVerificationError("Invalid or expired verification token.")

    user = session.scalar(select(User).where(User.id == record.user_id).with_for_update())

    if user is None:
        raise EmailVerificationError("Invalid or expired verification token.")

    record.used_at = now

    if user.email_verified_at is None:
        user.email_verified_at = now

    session.flush()

    return user
