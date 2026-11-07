import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.username_claim import UsernameClaim
from app.services.username_change import (
    USERNAME_CHANGE_COOLDOWN,
    UsernameChangeCooldownError,
    change_username,
)
from app.services.username_reservations import (
    UsernameUnavailableError,
    create_username_reservation,
)

_LONG_AGO = timedelta(days=31)


def _new_name() -> str:
    return f"chg_{uuid.uuid4().hex[:8]}"


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _make_user(
    db_session: Session,
    *,
    username: str | None = None,
    claim_age: timedelta = _LONG_AGO,
) -> User:
    user = User(
        email=f"username-change-{uuid.uuid4().hex}@example.com",
        display_name="Username Change Test",
        password_hash=None,
        is_active=True,
        email_verified_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.flush()

    if username is not None:
        db_session.add(
            UsernameClaim(
                username=username,
                claim_type="permanent",
                user_id=user.id,
                created_at=datetime.now(UTC) - claim_age,
            )
        )
        db_session.flush()
        db_session.expire(user, ["username_claim"])

    return user


def _claim_by_username(db_session: Session, username: str) -> UsernameClaim | None:
    return db_session.scalar(
        select(UsernameClaim)
        .where(UsernameClaim.username == username)
        .execution_options(populate_existing=True)
    )


def _permanent_claims(db_session: Session, user_id: uuid.UUID) -> list[UsernameClaim]:
    return list(
        db_session.scalars(
            select(UsernameClaim)
            .where(
                UsernameClaim.user_id == user_id,
                UsernameClaim.claim_type == "permanent",
            )
            .execution_options(populate_existing=True)
        ).all()
    )


def _count_claims(db_session: Session, *conditions: object) -> int:
    statement = select(func.count()).select_from(UsernameClaim).where(*conditions)
    return db_session.scalar(statement) or 0


def _make_unavailable_name(db_session: Session, kind: str) -> str:
    if kind == "seeded-reserved":
        return "admin"

    name = _new_name()

    if kind == "other-users-permanent":
        _make_user(db_session, username=name)
    elif kind == "active-reservation":
        db_session.add(
            UsernameClaim(
                username=name,
                claim_type="reservation",
                registration_attempt_id=uuid.uuid4(),
                token_hash="0" * 64,
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        )
        db_session.flush()
    else:
        raise ValueError(kind)

    return name


def test_user_without_a_claim_gets_a_permanent_claim(db_session: Session) -> None:
    user = _make_user(db_session)
    new_name = _new_name()
    reserved_before = _count_claims(db_session, UsernameClaim.claim_type == "reserved")

    changed = change_username(db_session, user.id, new_name)

    assert changed is True
    claims = _permanent_claims(db_session, user.id)
    assert [claim.username for claim in claims] == [new_name]
    assert user.username == new_name
    assert _count_claims(db_session, UsernameClaim.claim_type == "reserved") == reserved_before


def test_change_after_the_cooldown_burns_the_old_name_and_assigns_the_new_one(
    db_session: Session,
) -> None:
    old_name = _new_name()
    new_name = _new_name()
    user = _make_user(db_session, username=old_name)
    old_claim = _claim_by_username(db_session, old_name)
    assert old_claim is not None
    old_created_at = _aware(old_claim.created_at)

    changed = change_username(db_session, user.id, new_name)

    assert changed is True
    burned = _claim_by_username(db_session, old_name)
    assert burned is not None
    assert burned.id == old_claim.id
    assert burned.claim_type == "reserved"
    assert burned.user_id is None
    assert burned.registration_attempt_id is None
    assert burned.token_hash is None
    assert burned.expires_at is None

    claims = _permanent_claims(db_session, user.id)
    assert [claim.username for claim in claims] == [new_name]
    assert claims[0].id != old_claim.id
    assert _aware(claims[0].created_at) > old_created_at
    assert datetime.now(UTC) - _aware(claims[0].created_at) < timedelta(hours=1)
    assert user.username == new_name


def test_change_inside_the_cooldown_raises_and_changes_nothing(db_session: Session) -> None:
    old_name = _new_name()
    new_name = _new_name()
    user = _make_user(db_session, username=old_name, claim_age=timedelta(days=29))

    with pytest.raises(UsernameChangeCooldownError) as error:
        change_username(db_session, user.id, new_name)

    expected_seconds = int((USERNAME_CHANGE_COOLDOWN - timedelta(days=29)).total_seconds())
    assert abs(error.value.retry_after_seconds - expected_seconds) < 300
    claims = _permanent_claims(db_session, user.id)
    assert [claim.username for claim in claims] == [old_name]
    assert _claim_by_username(db_session, new_name) is None


@pytest.mark.parametrize(
    ("claim_age", "allowed"),
    [
        (USERNAME_CHANGE_COOLDOWN + timedelta(minutes=1), True),
        (USERNAME_CHANGE_COOLDOWN - timedelta(minutes=1), False),
    ],
    ids=["just-after-the-cooldown", "just-inside-the-cooldown"],
)
def test_cooldown_boundary(
    db_session: Session,
    claim_age: timedelta,
    allowed: bool,
) -> None:
    user = _make_user(db_session, username=_new_name(), claim_age=claim_age)

    if allowed:
        assert change_username(db_session, user.id, _new_name()) is True
    else:
        with pytest.raises(UsernameChangeCooldownError) as error:
            change_username(db_session, user.id, _new_name())
        assert 1 <= error.value.retry_after_seconds <= 120


def test_cooldown_is_checked_before_availability(db_session: Session) -> None:
    user = _make_user(db_session, username=_new_name(), claim_age=timedelta(days=1))

    with pytest.raises(UsernameChangeCooldownError):
        change_username(db_session, user.id, "admin")


@pytest.mark.parametrize(
    "claim_age",
    [timedelta(days=1), timedelta(days=40)],
    ids=["inside-cooldown", "after-cooldown"],
)
def test_requesting_the_current_name_changes_nothing(
    db_session: Session,
    claim_age: timedelta,
) -> None:
    name = _new_name()
    user = _make_user(db_session, username=name, claim_age=claim_age)
    claim_before = _claim_by_username(db_session, name)
    assert claim_before is not None
    claim_id = claim_before.id
    created_before = claim_before.created_at

    changed = change_username(db_session, user.id, name)

    assert changed is False
    claim_after = _claim_by_username(db_session, name)
    assert claim_after is not None
    assert claim_after.id == claim_id
    assert claim_after.claim_type == "permanent"
    assert claim_after.user_id == user.id
    assert claim_after.created_at == created_before


@pytest.mark.parametrize(
    "kind",
    ["seeded-reserved", "other-users-permanent", "active-reservation"],
)
def test_unavailable_name_raises_and_keeps_the_old_claim(
    db_session: Session,
    kind: str,
) -> None:
    old_name = _new_name()
    user = _make_user(db_session, username=old_name)
    target = _make_unavailable_name(db_session, kind)
    target_before = _claim_by_username(db_session, target)
    assert target_before is not None
    type_before = target_before.claim_type
    owner_before = target_before.user_id

    with pytest.raises(UsernameUnavailableError):
        change_username(db_session, user.id, target)

    claims = _permanent_claims(db_session, user.id)
    assert [claim.username for claim in claims] == [old_name]
    target_after = _claim_by_username(db_session, target)
    assert target_after is not None
    assert target_after.claim_type == type_before
    assert target_after.user_id == owner_before


def test_expired_reservation_on_the_new_name_is_replaced(db_session: Session) -> None:
    old_name = _new_name()
    new_name = _new_name()
    user = _make_user(db_session, username=old_name)
    db_session.add(
        UsernameClaim(
            username=new_name,
            claim_type="reservation",
            registration_attempt_id=uuid.uuid4(),
            token_hash="0" * 64,
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
    )
    db_session.flush()

    changed = change_username(db_session, user.id, new_name)

    assert changed is True
    assert _count_claims(db_session, UsernameClaim.username == new_name) == 1
    assert (
        _count_claims(
            db_session,
            UsernameClaim.username == new_name,
            UsernameClaim.claim_type == "permanent",
            UsernameClaim.user_id == user.id,
        )
        == 1
    )


def test_the_old_name_cannot_be_reclaimed_by_anyone(db_session: Session) -> None:
    old_name = _new_name()
    new_name = _new_name()
    user = _make_user(db_session, username=old_name)
    change_username(db_session, user.id, new_name)

    with pytest.raises(UsernameUnavailableError):
        create_username_reservation(db_session, old_name, uuid.uuid4())

    new_claim = _claim_by_username(db_session, new_name)
    assert new_claim is not None
    new_claim.created_at = datetime.now(UTC) - timedelta(days=40)
    db_session.flush()

    with pytest.raises(UsernameUnavailableError):
        change_username(db_session, user.id, old_name)

    claims = _permanent_claims(db_session, user.id)
    assert [claim.username for claim in claims] == [new_name]


def test_other_users_claims_are_untouched(db_session: Session) -> None:
    user = _make_user(db_session, username=_new_name())
    stranger_name = _new_name()
    stranger = _make_user(db_session, username=stranger_name)

    change_username(db_session, user.id, _new_name())

    stranger_claims = _permanent_claims(db_session, stranger.id)
    assert [claim.username for claim in stranger_claims] == [stranger_name]


def test_unknown_user_is_rejected(db_session: Session) -> None:
    with pytest.raises(RuntimeError):
        change_username(db_session, uuid.uuid4(), _new_name())
