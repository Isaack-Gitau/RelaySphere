import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.refresh_session import RefreshSession, RefreshTokenHistory
from app.models.user import User
from app.services.refresh_sessions import (
    InvalidRefreshTokenError,
    RefreshTokenReuseError,
    create_refresh_session,
    hash_refresh_token,
    revoke_refresh_session,
    rotate_refresh_token,
)


def create_verified_user(session: Session) -> User:
    user = User(
        email=f"refresh-{uuid.uuid4().hex}@example.com",
        display_name="Refresh Test User",
        password_hash=None,
        is_active=True,
        email_verified_at=datetime.now(UTC),
    )
    session.add(user)
    session.flush()
    return user


def test_refresh_reuse_error_requires_commit() -> None:
    error = RefreshTokenReuseError("replayed token")

    assert error.commit_required is True


def test_invalid_token_error_does_not_require_commit() -> None:
    error = InvalidRefreshTokenError("unknown token")

    assert error.commit_required is False


def test_session_invalidation_error_requires_commit() -> None:
    from app.services.refresh_sessions import RefreshSessionInvalidatedError

    error = RefreshSessionInvalidatedError("expired session")

    assert isinstance(error, InvalidRefreshTokenError)
    assert error.commit_required is True


def test_refresh_token_hash_is_sha256() -> None:
    token = "example-refresh-token"

    digest = hash_refresh_token(token)

    assert len(digest) == 64
    assert digest == hash_refresh_token(token)
    assert digest != token


@pytest.mark.parametrize("token", ["", None])
def test_hash_rejects_empty_or_missing_token(token: str | None) -> None:
    with pytest.raises(InvalidRefreshTokenError):
        hash_refresh_token(token)  # type: ignore[arg-type]


def test_create_refresh_session_stores_only_token_hash(
    db_session: Session,
) -> None:
    user = create_verified_user(db_session)

    raw_token = create_refresh_session(db_session, user.id)

    record = db_session.scalar(select(RefreshSession).where(RefreshSession.user_id == user.id))

    assert raw_token
    assert record is not None
    assert record.token_hash == hash_refresh_token(raw_token)
    assert record.token_hash != raw_token
    assert record.revoked_at is None
    assert record.expires_at > datetime.now(UTC)


def test_rotation_replaces_token_and_records_consumed_hash(
    db_session: Session,
) -> None:
    user = create_verified_user(db_session)
    original_token = create_refresh_session(db_session, user.id)

    replacement_token = rotate_refresh_token(db_session, original_token)

    record = db_session.scalar(select(RefreshSession).where(RefreshSession.user_id == user.id))
    history = db_session.scalar(
        select(RefreshTokenHistory).where(RefreshTokenHistory.session_id == record.id)
    )

    assert replacement_token != original_token
    assert record is not None
    assert record.token_hash == hash_refresh_token(replacement_token)
    assert record.last_used_at is not None
    assert history is not None
    assert history.token_hash == hash_refresh_token(original_token)


def test_reusing_old_token_revokes_session_after_multiple_rotations(
    db_session: Session,
) -> None:
    user = create_verified_user(db_session)
    first_token = create_refresh_session(db_session, user.id)
    second_token = rotate_refresh_token(db_session, first_token)
    third_token = rotate_refresh_token(db_session, second_token)

    with pytest.raises(RefreshTokenReuseError):
        rotate_refresh_token(db_session, first_token)

    record = db_session.scalar(select(RefreshSession).where(RefreshSession.user_id == user.id))

    assert record is not None
    assert record.revoked_at is not None
    assert record.token_hash == hash_refresh_token(third_token)


def test_expired_session_is_revoked_and_rejected(
    db_session: Session,
) -> None:
    user = create_verified_user(db_session)
    token = create_refresh_session(db_session, user.id)

    record = db_session.scalar(select(RefreshSession).where(RefreshSession.user_id == user.id))
    assert record is not None
    record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.flush()

    with pytest.raises(InvalidRefreshTokenError):
        rotate_refresh_token(db_session, token)

    assert record.revoked_at is not None


def test_logout_revokes_current_refresh_session(
    db_session: Session,
) -> None:
    user = create_verified_user(db_session)
    token = create_refresh_session(db_session, user.id)

    assert revoke_refresh_session(db_session, token) is True

    record = db_session.scalar(select(RefreshSession).where(RefreshSession.user_id == user.id))

    assert record is not None
    assert record.revoked_at is not None
    assert revoke_refresh_session(db_session, token) is False


def test_unknown_refresh_token_is_rejected(
    db_session: Session,
) -> None:
    with pytest.raises(InvalidRefreshTokenError):
        rotate_refresh_token(db_session, "unknown-refresh-token")


@pytest.mark.parametrize(
    ("is_active", "is_verified"),
    [
        (False, True),
        (True, False),
    ],
)
def test_refresh_rejects_inactive_or_unverified_account(
    db_session: Session,
    is_active: bool,
    is_verified: bool,
) -> None:
    user = create_verified_user(db_session)
    user.is_active = is_active
    user.email_verified_at = datetime.now(UTC) if is_verified else None
    db_session.flush()

    token = create_refresh_session(db_session, user.id)

    with pytest.raises(InvalidRefreshTokenError):
        rotate_refresh_token(db_session, token)

    record = db_session.scalar(select(RefreshSession).where(RefreshSession.user_id == user.id))

    assert record is not None
    assert record.revoked_at is not None
