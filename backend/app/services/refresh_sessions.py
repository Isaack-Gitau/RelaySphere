import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.refresh_session import RefreshSession, RefreshTokenHistory
from app.models.user import User

_REFRESH_TOKEN_BYTES = 48


class RefreshTokenError(Exception):
    """Base error for invalid refresh-token operations."""

    commit_required = False


class InvalidRefreshTokenError(RefreshTokenError):
    """Raised when a refresh token is invalid, expired, or unusable."""


class RefreshTokenReuseError(RefreshTokenError):
    """Raised when a previously consumed refresh token is reused."""

    commit_required = True


class RefreshSessionInvalidatedError(InvalidRefreshTokenError):
    """Raised when an unusable session has been marked for revocation."""

    commit_required = True


def hash_refresh_token(token: str) -> str:
    """Return a SHA-256 digest without storing the raw token."""
    if not isinstance(token, str) or not token:
        raise InvalidRefreshTokenError("Invalid refresh token.")

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_refresh_token() -> str:
    """Generate a cryptographically secure opaque refresh token."""
    return secrets.token_urlsafe(_REFRESH_TOKEN_BYTES)


def _expiry_from(now: datetime) -> datetime:
    """Calculate the fixed absolute session deadline."""
    lifetime_days = get_settings().session_absolute_lifetime_days
    return now + timedelta(days=lifetime_days)


def _as_utc(value: datetime) -> datetime:
    """Normalize database datetimes before comparing deadlines."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def session_is_expired(refresh_session: RefreshSession, now: datetime) -> bool:
    """Check fixed absolute expiry and the inactivity timeout."""
    settings = get_settings()
    absolute_expiry = _as_utc(refresh_session.expires_at)
    last_activity = refresh_session.last_used_at or refresh_session.created_at
    idle_expiry = _as_utc(last_activity) + timedelta(minutes=settings.session_idle_timeout_minutes)
    return absolute_expiry <= now or idle_expiry <= now


REAUTH_WINDOW = timedelta(minutes=10)


def is_recently_reauthenticated(marker: datetime | None, now: datetime) -> bool:
    """Return True only when the marker is set, not in the future, and under 10 minutes old."""
    if marker is None:
        return False
    age = now - _as_utc(marker)
    return timedelta(0) <= age < REAUTH_WINDOW


def create_refresh_session(
    session: Session,
    user_id: uuid.UUID,
    *,
    reauthenticated: bool = False,
) -> str:
    """Create a refresh session and return its raw token once."""
    now = datetime.now(UTC)
    raw_token = _new_refresh_token()

    refresh_session = RefreshSession(
        user_id=user_id,
        token_hash=hash_refresh_token(raw_token),
        expires_at=_expiry_from(now),
        reauthenticated_at=now if reauthenticated else None,
    )
    session.add(refresh_session)
    session.flush()

    return raw_token


def rotate_refresh_token(
    session: Session,
    raw_token: str,
) -> str:
    """Rotate a refresh token, revoking the session on detected replay."""
    token_hash = hash_refresh_token(raw_token)
    now = datetime.now(UTC)

    refresh_session = session.scalar(
        select(RefreshSession).where(RefreshSession.token_hash == token_hash).with_for_update()
    )

    if refresh_session is None:
        consumed_token = session.scalar(
            select(RefreshTokenHistory).where(RefreshTokenHistory.token_hash == token_hash)
        )

        if consumed_token is not None:
            refresh_session = session.scalar(
                select(RefreshSession)
                .where(RefreshSession.id == consumed_token.session_id)
                .with_for_update()
            )

            if refresh_session is not None and refresh_session.revoked_at is None:
                refresh_session.revoked_at = now

            raise RefreshTokenReuseError("A previously consumed refresh token was reused.")

        raise InvalidRefreshTokenError("Invalid refresh token.")

    if refresh_session.revoked_at is not None:
        raise InvalidRefreshTokenError("Refresh session is revoked.")

    if session_is_expired(refresh_session, now):
        refresh_session.revoked_at = now
        raise RefreshSessionInvalidatedError("Refresh session has expired or been idle too long.")

    user = session.scalar(select(User).where(User.id == refresh_session.user_id))

    if user is None or not user.is_active or user.email_verified_at is None:
        refresh_session.revoked_at = now
        raise RefreshSessionInvalidatedError("Refresh session is no longer available.")

    new_raw_token = _new_refresh_token()

    session.add(
        RefreshTokenHistory(
            session_id=refresh_session.id,
            token_hash=token_hash,
        )
    )
    refresh_session.token_hash = hash_refresh_token(new_raw_token)
    refresh_session.last_used_at = now
    # Keep expires_at fixed: rotation must not extend absolute session life.
    session.flush()

    return new_raw_token


def revoke_refresh_session(
    session: Session,
    raw_token: str,
) -> bool:
    """Revoke the session identified by its current refresh token."""
    token_hash = hash_refresh_token(raw_token)
    refresh_session = session.scalar(
        select(RefreshSession).where(RefreshSession.token_hash == token_hash).with_for_update()
    )

    if refresh_session is None or refresh_session.revoked_at is not None:
        return False

    refresh_session.revoked_at = datetime.now(UTC)
    session.flush()

    return True
