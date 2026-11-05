import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.email_change import (
    EMAIL_CHANGE_COOLDOWN_SECONDS,
    EMAIL_CHANGE_EMAIL_EVENT,
    EMAIL_CHANGE_TOKEN_EXPIRY_MINUTES,
)
from app.models.email_change_request import EmailChangeRequest
from app.models.email_verification_token import EmailVerificationToken
from app.models.password_reset_token import PasswordResetToken
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.services.email_change import (
    EmailChangeError,
    confirm_email_change,
    hash_email_change_token,
    request_email_change,
)
from app.services.email_verification import create_verification_token
from app.services.password_reset import create_password_reset_token
from app.services.refresh_sessions import create_refresh_session


def new_address() -> str:
    return f"new-{uuid.uuid4().hex}@example.com"


def create_change_user(
    session: Session,
    *,
    verified: bool = True,
    active: bool = True,
) -> User:
    user = User(
        email=f"{uuid.uuid4().hex}@example.com",
        display_name="Email Change Test",
        password_hash="unused-test-hash",
        is_active=active,
        email_verified_at=datetime.now(UTC) - timedelta(days=10) if verified else None,
    )
    session.add(user)
    session.flush()
    return user


def get_request(session: Session, raw_token: str) -> EmailChangeRequest | None:
    return session.scalar(
        select(EmailChangeRequest).where(
            EmailChangeRequest.token_hash == hash_email_change_token(raw_token)
        )
    )


def count_requests(session: Session, user_id: uuid.UUID) -> int:
    return (
        session.scalar(
            select(func.count())
            .select_from(EmailChangeRequest)
            .where(EmailChangeRequest.user_id == user_id)
        )
        or 0
    )


def count_active_requests(session: Session, user_id: uuid.UUID) -> int:
    return (
        session.scalar(
            select(func.count())
            .select_from(EmailChangeRequest)
            .where(
                EmailChangeRequest.user_id == user_id,
                EmailChangeRequest.used_at.is_(None),
                EmailChangeRequest.superseded_at.is_(None),
            )
        )
        or 0
    )


def backdate_requests(session: Session, user_id: uuid.UUID, **values: datetime) -> None:
    session.execute(
        update(EmailChangeRequest).where(EmailChangeRequest.user_id == user_id).values(**values)
    )
    session.expire_all()


def past_cooldown() -> datetime:
    return datetime.now(UTC) - timedelta(seconds=EMAIL_CHANGE_COOLDOWN_SECONDS + 1)


def make_request(session: Session, user: User, address: str | None = None) -> tuple[str, str]:
    target = address or new_address()
    result = request_email_change(session, user.id, target)
    assert result is not None
    return result[1], result[2]


def test_policy_constants() -> None:
    assert EMAIL_CHANGE_TOKEN_EXPIRY_MINUTES == 24 * 60
    assert EMAIL_CHANGE_EMAIL_EVENT == "email.email_change"


def test_request_returns_user_normalized_address_and_token(db_session: Session) -> None:
    user = create_change_user(db_session)
    target = new_address()

    result = request_email_change(db_session, user.id, f"  {target.upper()}  ")

    assert result is not None
    returned_user, new_email, raw_token = result
    assert returned_user.id == user.id
    assert new_email == target
    assert isinstance(raw_token, str)
    assert len(raw_token) >= 40


def test_request_stores_only_sha256_hash_and_new_address(db_session: Session) -> None:
    user = create_change_user(db_session)

    new_email, raw_token = make_request(db_session, user)

    record = get_request(db_session, raw_token)
    assert record is not None
    assert record.token_hash == hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    assert record.token_hash != raw_token
    assert record.new_email == new_email
    assert record.used_at is None
    assert record.superseded_at is None


def test_request_expires_after_configured_period(db_session: Session) -> None:
    user = create_change_user(db_session)
    before = datetime.now(UTC)

    _, raw_token = make_request(db_session, user)

    after = datetime.now(UTC)
    record = get_request(db_session, raw_token)
    expiry = timedelta(minutes=EMAIL_CHANGE_TOKEN_EXPIRY_MINUTES)
    assert record is not None
    assert record.expires_at >= before + expiry
    assert record.expires_at <= after + expiry


def test_request_does_not_change_the_current_address(db_session: Session) -> None:
    user = create_change_user(db_session)
    old_email = user.email

    make_request(db_session, user)

    assert user.email == old_email


def test_request_is_not_committed_by_service(db_session: Session) -> None:
    user = create_change_user(db_session)

    make_request(db_session, user)

    engine = db_session.get_bind().engine
    with engine.connect() as connection:
        visible = connection.scalar(
            select(EmailChangeRequest.id).where(EmailChangeRequest.user_id == user.id)
        )

    assert visible is None


def test_rolling_back_caller_transaction_removes_request(db_session: Session) -> None:
    user = create_change_user(db_session)

    _, raw_token = make_request(db_session, user)
    assert get_request(db_session, raw_token) is not None

    db_session.rollback()

    assert get_request(db_session, raw_token) is None


def test_request_for_current_address_creates_nothing(db_session: Session) -> None:
    user = create_change_user(db_session)

    result = request_email_change(db_session, user.id, f"  {user.email.upper()}  ")

    assert result is None
    assert count_requests(db_session, user.id) == 0


def test_request_for_address_held_by_another_account_creates_nothing(
    db_session: Session,
) -> None:
    user = create_change_user(db_session)
    other = create_change_user(db_session)

    result = request_email_change(db_session, user.id, other.email)

    assert result is None
    assert count_requests(db_session, user.id) == 0


def test_request_for_unknown_user_creates_nothing(db_session: Session) -> None:
    assert request_email_change(db_session, uuid.uuid4(), new_address()) is None


@pytest.mark.parametrize(
    "overrides",
    [{"verified": False}, {"active": False}],
    ids=["unverified", "inactive"],
)
def test_request_for_ineligible_user_creates_nothing(
    db_session: Session,
    overrides: dict[str, bool],
) -> None:
    user = create_change_user(db_session, **overrides)

    result = request_email_change(db_session, user.id, new_address())

    assert result is None
    assert count_requests(db_session, user.id) == 0


@pytest.mark.parametrize(
    "bad_address",
    ["", "   ", "no-at-sign", "a@b.com, c@d.com", "a b@example.com", "x@y.com\r\nBcc: z@w.com"],
)
def test_request_for_invalid_address_creates_nothing(
    db_session: Session,
    bad_address: str,
) -> None:
    user = create_change_user(db_session)

    assert request_email_change(db_session, user.id, bad_address) is None
    assert count_requests(db_session, user.id) == 0


def test_request_cooldown_blocks_immediate_second_request(db_session: Session) -> None:
    user = create_change_user(db_session)

    make_request(db_session, user)
    second = request_email_change(db_session, user.id, new_address())

    assert second is None
    assert count_requests(db_session, user.id) == 1


def test_new_request_supersedes_the_previous_one(db_session: Session) -> None:
    user = create_change_user(db_session)
    _, first_raw = make_request(db_session, user)
    backdate_requests(db_session, user.id, created_at=past_cooldown())

    _, second_raw = make_request(db_session, user)

    first = get_request(db_session, first_raw)
    second = get_request(db_session, second_raw)
    assert first is not None
    assert second is not None
    assert first.superseded_at is not None
    assert second.superseded_at is None
    assert count_requests(db_session, user.id) == 2
    assert count_active_requests(db_session, user.id) == 1

    with pytest.raises(EmailChangeError):
        confirm_email_change(db_session, first_raw)


def test_new_request_retires_an_expired_unused_request(db_session: Session) -> None:
    user = create_change_user(db_session)
    make_request(db_session, user)
    backdate_requests(
        db_session,
        user.id,
        created_at=past_cooldown(),
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )

    result = request_email_change(db_session, user.id, new_address())

    assert result is not None
    assert count_active_requests(db_session, user.id) == 1


def test_confirm_changes_address_and_marks_it_verified(db_session: Session) -> None:
    user = create_change_user(db_session)
    old_verified_at = user.email_verified_at
    new_email, raw_token = make_request(db_session, user)

    result = confirm_email_change(db_session, raw_token)

    assert result.id == user.id
    assert user.email == new_email
    assert user.email_verified_at is not None
    assert old_verified_at is not None
    assert user.email_verified_at > old_verified_at

    record = get_request(db_session, raw_token)
    assert record is not None
    assert record.used_at is not None
    assert count_active_requests(db_session, user.id) == 0


def test_confirm_revokes_every_unrevoked_session_without_creating_one(
    db_session: Session,
) -> None:
    user = create_change_user(db_session)
    create_refresh_session(db_session, user.id)
    create_refresh_session(db_session, user.id)
    create_refresh_session(db_session, user.id)

    rows = list(
        db_session.scalars(select(RefreshSession).where(RefreshSession.user_id == user.id)).all()
    )
    already_revoked_at = datetime.now(UTC) - timedelta(hours=1)
    rows[0].revoked_at = already_revoked_at
    db_session.flush()

    _, raw_token = make_request(db_session, user)
    confirm_email_change(db_session, raw_token)

    assert len(rows) == 3
    assert all(row.revoked_at is not None for row in rows)
    assert rows[0].revoked_at == already_revoked_at

    total = db_session.scalar(
        select(func.count()).select_from(RefreshSession).where(RefreshSession.user_id == user.id)
    )
    assert total == 3


def test_confirm_expires_pending_reset_and_verification_tokens(db_session: Session) -> None:
    user = create_change_user(db_session)
    create_password_reset_token(db_session, user.id)
    create_verification_token(db_session, user.id)
    _, raw_token = make_request(db_session, user)

    confirm_email_change(db_session, raw_token)

    now = datetime.now(UTC)
    reset_tokens = db_session.scalars(
        select(PasswordResetToken).where(PasswordResetToken.user_id == user.id)
    ).all()
    verification_tokens = db_session.scalars(
        select(EmailVerificationToken).where(EmailVerificationToken.user_id == user.id)
    ).all()

    assert len(reset_tokens) == 1
    assert len(verification_tokens) == 1
    assert reset_tokens[0].expires_at <= now
    assert verification_tokens[0].expires_at <= now
    assert reset_tokens[0].used_at is None
    assert verification_tokens[0].used_at is None


def test_old_address_no_longer_identifies_the_account(db_session: Session) -> None:
    user = create_change_user(db_session)
    old_email = user.email
    _, raw_token = make_request(db_session, user)

    confirm_email_change(db_session, raw_token)

    assert db_session.scalar(select(User.id).where(User.email == old_email)) is None


def test_confirm_token_is_single_use(db_session: Session) -> None:
    user = create_change_user(db_session)
    new_email, raw_token = make_request(db_session, user)

    confirm_email_change(db_session, raw_token)

    with pytest.raises(EmailChangeError):
        confirm_email_change(db_session, raw_token)

    assert user.email == new_email


def test_confirm_rejects_expired_request(db_session: Session) -> None:
    user = create_change_user(db_session)
    old_email = user.email
    _, raw_token = make_request(db_session, user)
    backdate_requests(db_session, user.id, expires_at=datetime.now(UTC) - timedelta(minutes=1))

    with pytest.raises(EmailChangeError):
        confirm_email_change(db_session, raw_token)

    refreshed = db_session.get(User, user.id)
    assert refreshed is not None
    assert refreshed.email == old_email


@pytest.mark.parametrize("bad_token", ["", "   ", "not-a-real-token"])
def test_confirm_rejects_unknown_or_blank_token(db_session: Session, bad_token: str) -> None:
    with pytest.raises(EmailChangeError):
        confirm_email_change(db_session, bad_token)


@pytest.mark.parametrize(
    "overrides",
    [{"verified": False}, {"active": False}],
    ids=["unverified", "inactive"],
)
def test_confirm_rechecks_account_eligibility(
    db_session: Session,
    overrides: dict[str, bool],
) -> None:
    user = create_change_user(db_session)
    old_email = user.email
    _, raw_token = make_request(db_session, user)

    if "verified" in overrides:
        user.email_verified_at = None
    if "active" in overrides:
        user.is_active = False
    db_session.flush()

    with pytest.raises(EmailChangeError):
        confirm_email_change(db_session, raw_token)

    assert user.email == old_email
    record = get_request(db_session, raw_token)
    assert record is not None
    assert record.used_at is None


def test_confirm_rejects_address_taken_after_the_request(db_session: Session) -> None:
    user = create_change_user(db_session)
    old_email = user.email
    target, raw_token = make_request(db_session, user)

    taker = User(
        email=target,
        display_name="Address Taker",
        password_hash="unused-test-hash",
        email_verified_at=datetime.now(UTC),
    )
    db_session.add(taker)
    db_session.flush()

    with pytest.raises(EmailChangeError):
        confirm_email_change(db_session, raw_token)

    assert user.email == old_email
    record = get_request(db_session, raw_token)
    assert record is not None
    assert record.used_at is None
