import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User

TOKEN_EXPIRY_MINUTES = 24 * 60
RESEND_COOLDOWN_SECONDS = 60


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


def resend_verification_token(
    session: Session,
    email: str,
) -> str | None:
    """Create a replacement token when the account is eligible and cooldown has passed."""
    user = session.scalar(select(User).where(User.email == email).with_for_update())

    if user is None or user.email_verified_at is not None:
        return None

    now = datetime.now(UTC)

    latest_token = session.scalar(
        select(EmailVerificationToken)
        .where(EmailVerificationToken.user_id == user.id)
        .order_by(EmailVerificationToken.created_at.desc())
        .limit(1)
    )

    if latest_token is not None:
        created_at = latest_token.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)

        elapsed = (now - created_at).total_seconds()
        if elapsed < RESEND_COOLDOWN_SECONDS:
            return None

    previous_tokens = session.scalars(
        select(EmailVerificationToken)
        .where(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.used_at.is_(None),
            EmailVerificationToken.expires_at > now,
        )
        .with_for_update()
    ).all()

    for token in previous_tokens:
        token.expires_at = now

    return create_verification_token(session, user.id)


def verify_email_token(
    session: Session,
    raw_token: str,
) -> User:
    """Verify a user's email using a valid, unused verification token."""
    if not isinstance(raw_token, str) or not raw_token.strip():
        raise EmailVerificationError("Invalid or expired verification token.")

    token_hash = hash_verification_token(raw_token)

    # Read the owner first without locking the token. All operations that
    # modify tokens acquire locks in user-then-token order.
    token_owner = session.scalar(
        select(EmailVerificationToken.user_id).where(
            EmailVerificationToken.token_hash == token_hash
        )
    )

    if token_owner is None:
        raise EmailVerificationError("Invalid or expired verification token.")

    user = session.scalar(select(User).where(User.id == token_owner).with_for_update())

    if user is None:
        raise EmailVerificationError("Invalid or expired verification token.")

    record = session.scalar(
        select(EmailVerificationToken)
        .where(EmailVerificationToken.token_hash == token_hash)
        .with_for_update()
    )

    now = datetime.now(UTC)

    if record is None or record.used_at is not None or record.expires_at <= now:
        raise EmailVerificationError("Invalid or expired verification token.")

    record.used_at = now

    if user.email_verified_at is None:
        user.email_verified_at = now

    session.flush()

    return user
