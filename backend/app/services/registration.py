from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.username_claim import UsernameClaim
from app.schemas.auth import RegisterRequest
from app.security.passwords import hash_password
from app.security.username_reservations import verify_reservation_token
from app.services.email_outbox import enqueue_email
from app.services.email_verification import create_verification_token
from app.services.username_reservations import (
    UsernameReservationExpiredError,
    UsernameReservationInvalidError,
)

VERIFICATION_EMAIL_EVENT = "email.verification"


_DUMMY_TOKEN_HASH = "0" * 64


class EmailAlreadyRegisteredError(Exception):
    """Indicate that an account already uses the requested email address."""


def _lock_and_validate_reservation(
    session: Session,
    registration: RegisterRequest,
) -> UsernameClaim:
    """Lock and return the matching, unexpired reservation row.

    Uses the same registration-attempt advisory lock key as reservation creation
    and release, then locks the row. A missing reservation costs the same token
    comparison as a wrong token, and expiry is reported only after the token
    matches. Database time decides expiry.
    """
    attempt_lock_key = f"relaysphere:registration-attempt:{registration.registration_attempt_id}"
    session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(attempt_lock_key, 0))))

    db_now = session.scalar(select(func.clock_timestamp()))
    if db_now is None:
        raise RuntimeError("Database clock is unavailable.")

    claim = session.scalar(
        select(UsernameClaim)
        .where(
            UsernameClaim.id == registration.reservation_id,
            UsernameClaim.claim_type == "reservation",
            UsernameClaim.registration_attempt_id == registration.registration_attempt_id,
            UsernameClaim.username == registration.username,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )

    stored_hash = claim.token_hash if claim is not None and claim.token_hash else _DUMMY_TOKEN_HASH
    token_matches = verify_reservation_token(registration.reservation_token, stored_hash)

    if claim is None or not token_matches:
        raise UsernameReservationInvalidError

    if claim.expires_at is None or claim.expires_at <= db_now:
        raise UsernameReservationExpiredError

    return claim


def _burn_reservation(session: Session, claim: UsernameClaim) -> None:
    """Turn a valid reservation into an ownerless reserved claim.

    A duplicate email must leave the same observable username state as a real
    registration: unavailable, and not releasable or reusable with the reservation
    credentials. All state-dependent columns change in one UPDATE so the
    claim_state_valid check holds. The caller commits.
    """
    claim.claim_type = "reserved"
    claim.user_id = None
    claim.registration_attempt_id = None
    claim.token_hash = None
    claim.expires_at = None
    session.flush()


def register_user(
    session: Session,
    registration: RegisterRequest,
) -> User:
    """Create an unverified user without committing the caller's transaction."""
    email = str(registration.email).strip().lower()

    # Hash before the duplicate lookup so existing and new addresses both pay for
    # Argon2 and response timing does not reveal which emails are registered.
    password_hash = hash_password(registration.password)

    # Validate the reservation before the email lookup so a bad reservation behaves
    # identically for new and existing addresses. A duplicate email burns a valid
    # reservation into an ownerless reserved claim, so the username ends up
    # unavailable exactly as it does after a real registration.
    claim = _lock_and_validate_reservation(session, registration)

    existing_user_id = session.scalar(select(User.id).where(User.email == email))
    if existing_user_id is not None:
        _burn_reservation(session, claim)
        raise EmailAlreadyRegisteredError("An account with this email address already exists.")

    user = User(
        email=email,
        display_name=registration.display_name,
        password_hash=password_hash,
        email_verified_at=None,
    )

    try:
        with session.begin_nested():
            session.add(user)
            session.flush()
            session.refresh(user)
    except IntegrityError as exc:
        existing_user_id = session.scalar(select(User.id).where(User.email == email))
        if existing_user_id is not None:
            _burn_reservation(session, claim)
            raise EmailAlreadyRegisteredError(
                "An account with this email address already exists."
            ) from exc
        raise

    # Convert the reservation to the permanent claim in the same transaction. All
    # state-dependent columns change in one UPDATE so the claim_state_valid check holds.
    claim.claim_type = "permanent"
    claim.user_id = user.id
    claim.registration_attempt_id = None
    claim.token_hash = None
    claim.expires_at = None
    session.flush()
    session.expire(user, ["username_claim"])

    return user


def register_user_with_verification_token(
    session: Session,
    registration: RegisterRequest,
) -> tuple[User, str]:
    """Create a user, verification token, and encrypted email job atomically."""
    user = register_user(session, registration)
    raw_token = create_verification_token(session, user.id)

    enqueue_email(
        session,
        VERIFICATION_EMAIL_EVENT,
        {
            "recipient": user.email,
            "display_name": user.display_name,
            "verification_token": raw_token,
        },
    )

    return user, raw_token
