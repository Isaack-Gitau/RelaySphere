import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.password_reset import (
    PASSWORD_RESET_COOLDOWN_SECONDS,
    PASSWORD_RESET_TOKEN_EXPIRY_MINUTES,
)
from app.models.password_reset_token import PasswordResetToken
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.security.passwords import hash_password

_INVALID_TOKEN_MESSAGE = "Invalid or expired reset token."


class PasswordResetError(Exception):
    """Indicate that a password reset token cannot be used."""


def hash_password_reset_token(token: str) -> str:
    """Return a SHA-256 hash of a password reset token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _as_utc(value: datetime) -> datetime:
    """Normalize database datetimes before comparing deadlines."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _can_reset_password(user: User) -> bool:
    """Return True only for active, verified accounts that have a password."""
    return bool(user.is_active and user.email_verified_at is not None and user.password_hash)


def _expire_unused_tokens(session: Session, user_id: uuid.UUID, now: datetime) -> None:
    """Expire every unused, unexpired reset token the user still holds."""
    older_tokens = session.scalars(
        select(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user_id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .with_for_update()
    ).all()

    for token in older_tokens:
        token.expires_at = now


def create_password_reset_token(
    session: Session,
    user_id: uuid.UUID,
) -> str:
    """Create a reset token in the caller's transaction, expiring older unused ones."""
    now = datetime.now(UTC)
    _expire_unused_tokens(session, user_id, now)

    raw_token = secrets.token_urlsafe(32)
    record = PasswordResetToken(
        user_id=user_id,
        token_hash=hash_password_reset_token(raw_token),
        expires_at=now + timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRY_MINUTES),
    )

    session.add(record)
    session.flush()

    return raw_token


def request_password_reset(
    session: Session,
    email: str,
) -> tuple[User, str] | None:
    """Create a reset token when the account is eligible and the cooldown has passed.

    Returns None for unknown, inactive, unverified, or passwordless accounts and
    during the cooldown, so callers can give one generic response in every case.
    """
    normalized_email = email.strip().lower()

    # Lock order: user first, then tokens.
    user = session.scalar(select(User).where(User.email == normalized_email).with_for_update())

    if user is None or not _can_reset_password(user):
        return None

    now = datetime.now(UTC)

    latest_token = session.scalar(
        select(PasswordResetToken)
        .where(PasswordResetToken.user_id == user.id)
        .order_by(PasswordResetToken.created_at.desc())
        .limit(1)
    )

    if latest_token is not None:
        elapsed = (now - _as_utc(latest_token.created_at)).total_seconds()
        if elapsed < PASSWORD_RESET_COOLDOWN_SECONDS:
            return None

    raw_token = create_password_reset_token(session, user.id)
    return user, raw_token


def confirm_password_reset(
    session: Session,
    raw_token: str,
    new_password: str,
) -> User:
    """Use a reset token to set a new password and revoke all refresh sessions.

    This does not create a session: the user must sign in with the new password.
    """
    if not isinstance(raw_token, str) or not raw_token.strip():
        raise PasswordResetError(_INVALID_TOKEN_MESSAGE)

    if not isinstance(new_password, str) or not new_password:
        raise PasswordResetError("A new password is required.")

    # Hash before taking row locks so Argon2 work does not hold them.
    new_password_hash = hash_password(new_password)
    token_hash = hash_password_reset_token(raw_token)

    # Read the owner without locking. Lock order is user first, then token.
    token_owner = session.scalar(
        select(PasswordResetToken.user_id).where(PasswordResetToken.token_hash == token_hash)
    )

    if token_owner is None:
        raise PasswordResetError(_INVALID_TOKEN_MESSAGE)

    user = session.scalar(select(User).where(User.id == token_owner).with_for_update())

    if user is None:
        raise PasswordResetError(_INVALID_TOKEN_MESSAGE)

    record = session.scalar(
        select(PasswordResetToken)
        .where(PasswordResetToken.token_hash == token_hash)
        .with_for_update()
    )

    now = datetime.now(UTC)

    if record is None or record.used_at is not None or _as_utc(record.expires_at) <= now:
        raise PasswordResetError(_INVALID_TOKEN_MESSAGE)

    if not _can_reset_password(user):
        raise PasswordResetError(_INVALID_TOKEN_MESSAGE)

    record.used_at = now
    _expire_unused_tokens(session, user.id, now)

    user.password_hash = new_password_hash

    active_sessions = session.scalars(
        select(RefreshSession)
        .where(
            RefreshSession.user_id == user.id,
            RefreshSession.revoked_at.is_(None),
        )
        .with_for_update()
    ).all()

    for refresh_session in active_sessions:
        refresh_session.revoked_at = now

    session.flush()

    return user
