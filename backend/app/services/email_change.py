import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.email_change import (
    EMAIL_CHANGE_COOLDOWN_SECONDS,
    EMAIL_CHANGE_TOKEN_EXPIRY_MINUTES,
)
from app.models.email_change_request import EmailChangeRequest
from app.models.email_verification_token import EmailVerificationToken
from app.models.password_reset_token import PasswordResetToken
from app.models.refresh_session import RefreshSession
from app.models.user import User

_INVALID_TOKEN_MESSAGE = "Invalid or expired confirmation token."


class EmailChangeError(Exception):
    """Indicate that an email change token cannot be used."""


def hash_email_change_token(token: str) -> str:
    """Return a SHA-256 hash of an email change token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _as_utc(value: datetime) -> datetime:
    """Normalize database datetimes before comparing deadlines."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _normalize_email(value: object) -> str | None:
    """Return a lowercase address, or None when it cannot be a single mailbox."""
    if not isinstance(value, str):
        return None

    normalized = value.strip().lower()

    if not normalized or len(normalized) > 320 or "@" not in normalized:
        return None

    if any(character.isspace() or character in "\r\n,;<>" for character in normalized):
        return None

    return normalized


def _can_change_email(user: User) -> bool:
    """Return True only for active accounts whose current address is verified."""
    return bool(user.is_active and user.email_verified_at is not None)


def _supersede_active_requests(session: Session, user_id: uuid.UUID, now: datetime) -> None:
    """Retire every unused request, including expired ones, for the user."""
    active_requests = session.scalars(
        select(EmailChangeRequest)
        .where(
            EmailChangeRequest.user_id == user_id,
            EmailChangeRequest.used_at.is_(None),
            EmailChangeRequest.superseded_at.is_(None),
        )
        .with_for_update()
    ).all()

    for active_request in active_requests:
        active_request.superseded_at = now


def request_email_change(
    session: Session,
    user_id: uuid.UUID,
    new_email: str,
) -> tuple[User, str, str] | None:
    """Create an email change request in the caller's transaction.

    Returns (user, normalized_new_email, raw_token), or None when nothing should be
    sent: unknown or ineligible user, invalid address, the current address, an
    address held by another account, or the cooldown. Callers give one generic
    response in every case so the endpoint cannot be used to probe accounts.
    """
    normalized = _normalize_email(new_email)

    if normalized is None:
        return None

    # Lock order: user first, then the user's requests.
    user = session.scalar(select(User).where(User.id == user_id).with_for_update())

    if user is None or not _can_change_email(user):
        return None

    if normalized == user.email.strip().lower():
        return None

    address_holder = session.scalar(
        select(User.id).where(User.email == normalized, User.id != user.id)
    )

    if address_holder is not None:
        return None

    now = datetime.now(UTC)

    latest_request = session.scalar(
        select(EmailChangeRequest)
        .where(EmailChangeRequest.user_id == user.id)
        .order_by(EmailChangeRequest.created_at.desc())
        .limit(1)
    )

    if latest_request is not None:
        elapsed = (now - _as_utc(latest_request.created_at)).total_seconds()
        if elapsed < EMAIL_CHANGE_COOLDOWN_SECONDS:
            return None

    _supersede_active_requests(session, user.id, now)
    # Flush so the partial unique index sees the old rows retired before the insert.
    session.flush()

    raw_token = secrets.token_urlsafe(32)
    session.add(
        EmailChangeRequest(
            user_id=user.id,
            new_email=normalized,
            token_hash=hash_email_change_token(raw_token),
            expires_at=now + timedelta(minutes=EMAIL_CHANGE_TOKEN_EXPIRY_MINUTES),
        )
    )
    session.flush()

    return user, normalized, raw_token


def confirm_email_change(
    session: Session,
    raw_token: str,
) -> User:
    """Apply a pending email change.

    Sets the new address as verified, revokes every refresh session of the user,
    and expires pending password reset and verification tokens, which were issued
    for the old address. This does not create a session.
    """
    if not isinstance(raw_token, str) or not raw_token.strip():
        raise EmailChangeError(_INVALID_TOKEN_MESSAGE)

    token_hash = hash_email_change_token(raw_token)

    # Read the owner without locking. Lock order is user first, then the request.
    token_owner = session.scalar(
        select(EmailChangeRequest.user_id).where(EmailChangeRequest.token_hash == token_hash)
    )

    if token_owner is None:
        raise EmailChangeError(_INVALID_TOKEN_MESSAGE)

    user = session.scalar(select(User).where(User.id == token_owner).with_for_update())

    if user is None:
        raise EmailChangeError(_INVALID_TOKEN_MESSAGE)

    record = session.scalar(
        select(EmailChangeRequest)
        .where(EmailChangeRequest.token_hash == token_hash)
        .with_for_update()
    )

    now = datetime.now(UTC)

    if (
        record is None
        or record.used_at is not None
        or record.superseded_at is not None
        or _as_utc(record.expires_at) <= now
    ):
        raise EmailChangeError(_INVALID_TOKEN_MESSAGE)

    if not _can_change_email(user):
        raise EmailChangeError(_INVALID_TOKEN_MESSAGE)

    new_email = record.new_email

    # Recheck uniqueness inside this transaction; the unique index is the backstop.
    address_holder = session.scalar(
        select(User.id).where(User.email == new_email, User.id != user.id)
    )

    if address_holder is not None:
        raise EmailChangeError(_INVALID_TOKEN_MESSAGE)

    try:
        with session.begin_nested():
            user.email = new_email
            user.email_verified_at = now
            session.flush()
    except IntegrityError as exc:
        raise EmailChangeError(_INVALID_TOKEN_MESSAGE) from exc

    record.used_at = now

    for reset_token in session.scalars(
        select(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .with_for_update()
    ).all():
        reset_token.expires_at = now

    for verification_token in session.scalars(
        select(EmailVerificationToken)
        .where(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.used_at.is_(None),
            EmailVerificationToken.expires_at > now,
        )
        .with_for_update()
    ).all():
        verification_token.expires_at = now

    active_sessions = session.scalars(
        select(RefreshSession)
        .where(
            RefreshSession.user_id == user.id,
            RefreshSession.revoked_at.is_(None),
        )
        .order_by(RefreshSession.id)
        .with_for_update()
    ).all()

    for refresh_session in active_sessions:
        refresh_session.revoked_at = now

    session.flush()

    return user
