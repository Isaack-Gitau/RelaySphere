import uuid
from datetime import UTC, datetime, timedelta
from math import ceil

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.username_claim import UsernameClaim
from app.services.username_reservations import UsernameUnavailableError

USERNAME_CHANGE_COOLDOWN = timedelta(days=30)


class UsernameChangeCooldownError(Exception):
    """Indicate that the current username was assigned too recently to change."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("The username was assigned too recently to change.")
        self.retry_after_seconds = retry_after_seconds


def _as_utc(value: datetime) -> datetime:
    """Normalize database datetimes before comparing deadlines."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _database_now(session: Session) -> datetime:
    """Return the database clock, which decides every deadline."""
    db_now = session.scalar(select(func.clock_timestamp()))
    if db_now is None:
        raise RuntimeError("Database clock is unavailable.")
    return _as_utc(db_now)


def _acquire_username_locks(session: Session, usernames: set[str]) -> None:
    """Serialize competing changes and reservations for every username involved.

    Uses the same key format as username reservation creation and takes the keys in
    sorted order, so two users swapping names cannot deadlock each other.
    """
    for lock_key in sorted(f"relaysphere:username:{username}" for username in usernames):
        session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(lock_key, 0))))


def change_username(
    session: Session,
    user_id: uuid.UUID,
    new_username: str,
) -> bool:
    """Move a user to a new permanent username inside the caller's transaction.

    Returns False when the user already has that username and nothing changed.
    Raises UsernameChangeCooldownError when the current username was assigned less
    than USERNAME_CHANGE_COOLDOWN ago, and UsernameUnavailableError when the new
    name is held by anyone else. The cooldown is checked first, so a user who is
    waiting cannot use this to learn which names are free.

    Lock order: user row, then the advisory locks for the old and new names in sorted
    order, then the claim rows. The old name becomes an ownerless reserved claim, so
    nobody, including the former owner, can take it afterwards. The caller commits.
    """
    # The user row lock freezes this user's own claim: nothing else changes it.
    user = session.scalar(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )

    if user is None:
        raise RuntimeError("The user no longer exists.")

    current_claim = session.scalar(
        select(UsernameClaim).where(
            UsernameClaim.user_id == user_id,
            UsernameClaim.claim_type == "permanent",
        )
    )
    old_username = current_claim.username if current_claim is not None else None

    if old_username == new_username:
        return False

    if current_claim is not None:
        cooldown_ends_at = _as_utc(current_claim.created_at) + USERNAME_CHANGE_COOLDOWN
        remaining = cooldown_ends_at - _database_now(session)
        if remaining > timedelta(0):
            raise UsernameChangeCooldownError(max(1, ceil(remaining.total_seconds())))

    usernames = {new_username}
    if old_username is not None:
        usernames.add(old_username)
    _acquire_username_locks(session, usernames)

    db_now = _database_now(session)

    locked_current = None
    if current_claim is not None:
        locked_current = session.scalar(
            select(UsernameClaim)
            .where(UsernameClaim.id == current_claim.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if locked_current is None:
            raise RuntimeError("The current username claim disappeared.")

    target_claim = session.scalar(
        select(UsernameClaim)
        .where(UsernameClaim.username == new_username)
        .with_for_update()
        .execution_options(populate_existing=True)
    )

    if target_claim is not None:
        target_is_expired_reservation = (
            target_claim.claim_type == "reservation"
            and target_claim.expires_at is not None
            and _as_utc(target_claim.expires_at) <= db_now
        )
        if not target_is_expired_reservation:
            raise UsernameUnavailableError

    if locked_current is not None:
        # One UPDATE changes every state column so claim_state_valid holds.
        locked_current.claim_type = "reserved"
        locked_current.user_id = None
        locked_current.registration_attempt_id = None
        locked_current.token_hash = None
        locked_current.expires_at = None
        session.flush()

    if target_claim is not None:
        session.delete(target_claim)
        session.flush()

    session.add(UsernameClaim(username=new_username, claim_type="permanent", user_id=user_id))
    session.flush()
    session.expire(user, ["username_claim"])

    return True
