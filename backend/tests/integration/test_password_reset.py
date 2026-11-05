import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.password_reset import (
    PASSWORD_RESET_COOLDOWN_SECONDS,
    PASSWORD_RESET_TOKEN_EXPIRY_MINUTES,
)
from app.models.password_reset_token import PasswordResetToken
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.security.passwords import hash_password, verify_password
from app.services.password_reset import (
    PasswordResetError,
    confirm_password_reset,
    create_password_reset_token,
    hash_password_reset_token,
    request_password_reset,
)
from app.services.refresh_sessions import create_refresh_session

OLD_PASSWORD = "old-password-for-tests-1"
NEW_PASSWORD = "new-password-for-tests-2"


def create_reset_user(
    session: Session,
    *,
    verified: bool = True,
    active: bool = True,
    with_password: bool = True,
) -> User:
    """Create a user with a real Argon2 hash unless a passwordless user is requested."""
    user = User(
        email=f"{uuid.uuid4().hex}@example.com",
        display_name="Reset Test",
        password_hash=hash_password(OLD_PASSWORD) if with_password else None,
        is_active=active,
        email_verified_at=datetime.now(UTC) if verified else None,
    )
    session.add(user)
    session.flush()
    return user


def count_tokens(session: Session, user_id: uuid.UUID) -> int:
    return (
        session.scalar(
            select(func.count())
            .select_from(PasswordResetToken)
            .where(PasswordResetToken.user_id == user_id)
        )
        or 0
    )


def get_token(session: Session, raw_token: str) -> PasswordResetToken | None:
    return session.scalar(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == hash_password_reset_token(raw_token)
        )
    )


def test_create_token_returns_secure_raw_token(db_session: Session) -> None:
    user = create_reset_user(db_session)

    raw_token = create_password_reset_token(db_session, user.id)

    assert isinstance(raw_token, str)
    assert len(raw_token) >= 40


def test_token_stores_only_sha256_hash(db_session: Session) -> None:
    user = create_reset_user(db_session)

    raw_token = create_password_reset_token(db_session, user.id)

    record = get_token(db_session, raw_token)

    assert record is not None
    assert record.token_hash == hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    assert record.token_hash != raw_token
    assert len(record.token_hash) == 64


def test_token_expires_after_configured_period(db_session: Session) -> None:
    user = create_reset_user(db_session)
    before_creation = datetime.now(UTC)

    raw_token = create_password_reset_token(db_session, user.id)

    after_creation = datetime.now(UTC)
    record = get_token(db_session, raw_token)
    expiry = timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRY_MINUTES)

    assert PASSWORD_RESET_TOKEN_EXPIRY_MINUTES == 30
    assert record is not None
    assert record.expires_at >= before_creation + expiry
    assert record.expires_at <= after_creation + expiry
    assert record.used_at is None


def test_token_is_not_committed_by_service(db_session: Session) -> None:
    user = create_reset_user(db_session)

    create_password_reset_token(db_session, user.id)

    engine = db_session.get_bind().engine
    with engine.connect() as connection:
        visible = connection.scalar(
            select(PasswordResetToken.id).where(PasswordResetToken.user_id == user.id)
        )

    assert visible is None


def test_rolling_back_caller_transaction_removes_token(db_session: Session) -> None:
    user = create_reset_user(db_session)

    raw_token = create_password_reset_token(db_session, user.id)
    assert get_token(db_session, raw_token) is not None

    db_session.rollback()

    assert get_token(db_session, raw_token) is None


def test_issuing_a_token_expires_older_unused_tokens(db_session: Session) -> None:
    user = create_reset_user(db_session)

    first_raw = create_password_reset_token(db_session, user.id)
    second_raw = create_password_reset_token(db_session, user.id)

    first = get_token(db_session, first_raw)
    second = get_token(db_session, second_raw)
    now = datetime.now(UTC)

    assert first is not None
    assert second is not None
    assert first.expires_at <= now
    assert second.expires_at > now


def test_request_for_eligible_user_returns_user_and_token(db_session: Session) -> None:
    user = create_reset_user(db_session)

    result = request_password_reset(db_session, user.email)

    assert result is not None
    returned_user, raw_token = result
    assert returned_user.id == user.id
    assert get_token(db_session, raw_token) is not None


def test_request_normalizes_email_case_and_whitespace(db_session: Session) -> None:
    user = create_reset_user(db_session)

    result = request_password_reset(db_session, f"  {user.email.upper()}  ")

    assert result is not None
    assert result[0].id == user.id


def test_request_for_unknown_email_creates_nothing(db_session: Session) -> None:
    before = db_session.scalar(select(func.count()).select_from(PasswordResetToken))

    result = request_password_reset(db_session, f"{uuid.uuid4().hex}@example.com")

    after = db_session.scalar(select(func.count()).select_from(PasswordResetToken))
    assert result is None
    assert after == before


@pytest.mark.parametrize(
    "overrides",
    [
        {"verified": False},
        {"active": False},
        {"with_password": False},
    ],
    ids=["unverified", "inactive", "no_password"],
)
def test_request_for_ineligible_account_creates_nothing(
    db_session: Session,
    overrides: dict[str, bool],
) -> None:
    user = create_reset_user(db_session, **overrides)

    result = request_password_reset(db_session, user.email)

    assert result is None
    assert count_tokens(db_session, user.id) == 0


def test_request_cooldown_blocks_immediate_second_request(db_session: Session) -> None:
    user = create_reset_user(db_session)

    first = request_password_reset(db_session, user.email)
    second = request_password_reset(db_session, user.email)

    assert first is not None
    assert second is None
    assert count_tokens(db_session, user.id) == 1


def test_request_after_cooldown_issues_new_token_and_expires_old(db_session: Session) -> None:
    user = create_reset_user(db_session)

    first = request_password_reset(db_session, user.email)
    assert first is not None
    first_raw = first[1]

    db_session.execute(
        update(PasswordResetToken)
        .where(PasswordResetToken.user_id == user.id)
        .values(
            created_at=datetime.now(UTC) - timedelta(seconds=PASSWORD_RESET_COOLDOWN_SECONDS + 1)
        )
    )
    db_session.expire_all()

    second = request_password_reset(db_session, user.email)

    assert second is not None
    old_record = get_token(db_session, first_raw)
    assert old_record is not None
    assert old_record.expires_at <= datetime.now(UTC)
    assert count_tokens(db_session, user.id) == 2


def test_confirm_sets_new_password_and_marks_token_used(db_session: Session) -> None:
    user = create_reset_user(db_session)
    raw_token = create_password_reset_token(db_session, user.id)

    result = confirm_password_reset(db_session, raw_token, NEW_PASSWORD)

    assert result.id == user.id
    assert user.password_hash is not None
    assert verify_password(NEW_PASSWORD, user.password_hash)
    assert not verify_password(OLD_PASSWORD, user.password_hash)

    record = get_token(db_session, raw_token)
    assert record is not None
    assert record.used_at is not None


def test_confirm_revokes_every_unrevoked_session_without_creating_one(
    db_session: Session,
) -> None:
    user = create_reset_user(db_session)
    create_refresh_session(db_session, user.id)
    create_refresh_session(db_session, user.id)
    create_refresh_session(db_session, user.id)

    rows = list(
        db_session.scalars(select(RefreshSession).where(RefreshSession.user_id == user.id)).all()
    )
    already_revoked_at = datetime.now(UTC) - timedelta(hours=1)
    rows[0].revoked_at = already_revoked_at
    db_session.flush()

    raw_token = create_password_reset_token(db_session, user.id)
    confirm_password_reset(db_session, raw_token, NEW_PASSWORD)

    assert len(rows) == 3
    assert all(row.revoked_at is not None for row in rows)
    assert rows[0].revoked_at == already_revoked_at

    total_sessions = db_session.scalar(
        select(func.count()).select_from(RefreshSession).where(RefreshSession.user_id == user.id)
    )
    assert total_sessions == 3


def test_confirm_expires_other_unused_tokens(db_session: Session) -> None:
    user = create_reset_user(db_session)
    raw_token = create_password_reset_token(db_session, user.id)

    other = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_password_reset_token("manually-inserted-other-token"),
        expires_at=datetime.now(UTC) + timedelta(minutes=20),
    )
    db_session.add(other)
    db_session.flush()

    confirm_password_reset(db_session, raw_token, NEW_PASSWORD)

    assert other.used_at is None
    assert other.expires_at <= datetime.now(UTC)


def test_confirm_token_is_single_use(db_session: Session) -> None:
    user = create_reset_user(db_session)
    raw_token = create_password_reset_token(db_session, user.id)

    confirm_password_reset(db_session, raw_token, NEW_PASSWORD)

    with pytest.raises(PasswordResetError):
        confirm_password_reset(db_session, raw_token, "yet-another-password-3")

    assert user.password_hash is not None
    assert verify_password(NEW_PASSWORD, user.password_hash)


def test_confirm_rejects_expired_token(db_session: Session) -> None:
    user = create_reset_user(db_session)
    raw_token = create_password_reset_token(db_session, user.id)

    db_session.execute(
        update(PasswordResetToken)
        .where(PasswordResetToken.user_id == user.id)
        .values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
    )
    db_session.expire_all()

    with pytest.raises(PasswordResetError):
        confirm_password_reset(db_session, raw_token, NEW_PASSWORD)

    refreshed = db_session.get(User, user.id)
    assert refreshed is not None
    assert refreshed.password_hash is not None
    assert verify_password(OLD_PASSWORD, refreshed.password_hash)


@pytest.mark.parametrize("bad_token", ["", "   ", "not-a-real-token"])
def test_confirm_rejects_unknown_or_blank_token(db_session: Session, bad_token: str) -> None:
    with pytest.raises(PasswordResetError):
        confirm_password_reset(db_session, bad_token, NEW_PASSWORD)


def test_confirm_rejects_blank_new_password(db_session: Session) -> None:
    user = create_reset_user(db_session)
    raw_token = create_password_reset_token(db_session, user.id)

    with pytest.raises(PasswordResetError):
        confirm_password_reset(db_session, raw_token, "")

    record = get_token(db_session, raw_token)
    assert record is not None
    assert record.used_at is None


@pytest.mark.parametrize(
    "overrides",
    [{"verified": False}, {"active": False}],
    ids=["unverified", "inactive"],
)
def test_confirm_rechecks_account_eligibility(
    db_session: Session,
    overrides: dict[str, bool],
) -> None:
    user = create_reset_user(db_session)
    raw_token = create_password_reset_token(db_session, user.id)

    if "verified" in overrides:
        user.email_verified_at = None
    if "active" in overrides:
        user.is_active = False
    db_session.flush()

    with pytest.raises(PasswordResetError):
        confirm_password_reset(db_session, raw_token, NEW_PASSWORD)

    assert user.password_hash is not None
    assert verify_password(OLD_PASSWORD, user.password_hash)
    record = get_token(db_session, raw_token)
    assert record is not None
    assert record.used_at is None
