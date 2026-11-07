import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.username_claim import UsernameClaim
from app.security.username_reservations import (
    generate_reservation_token,
    hash_reservation_token,
    verify_reservation_token,
)

RESERVATION_LIFETIME = timedelta(minutes=5)


class UsernameUnavailableError(Exception):
    """The requested username is already reserved or permanently claimed."""


class UsernameReservationExistsError(Exception):
    """The registration attempt already owns an active reservation."""


@dataclass(frozen=True, slots=True)
class CreatedUsernameReservation:
    reservation_id: uuid.UUID
    username: str
    reservation_token: str
    expires_at: datetime


def _acquire_reservation_locks(
    session: Session,
    username: str,
    registration_attempt_id: uuid.UUID,
) -> None:
    """Serialize competing requests for the username and registration attempt."""
    lock_keys = sorted(
        (
            f"relaysphere:username:{username}",
            f"relaysphere:registration-attempt:{registration_attempt_id}",
        )
    )

    for lock_key in lock_keys:
        session.execute(
            select(
                func.pg_advisory_xact_lock(
                    func.hashtextextended(lock_key, 0)
                )
            )
        )


def create_username_reservation(
    session: Session,
    username: str,
    registration_attempt_id: uuid.UUID,
) -> CreatedUsernameReservation:
    """Create a five-minute reservation inside the caller's transaction.

    PostgreSQL advisory transaction locks serialize requests even when the
    username or registration-attempt row does not yet exist. Database unique
    constraints remain the final integrity safeguards.

    The caller is responsible for committing or rolling back the transaction.
    """
    _acquire_reservation_locks(session, username, registration_attempt_id)

    db_now = session.scalar(select(func.clock_timestamp()))
    if db_now is None:
        raise RuntimeError("Database clock is unavailable.")

    username_claim = session.scalar(
        select(UsernameClaim)
        .where(UsernameClaim.username == username)
        .with_for_update()
    )

    attempt_claim = session.scalar(
        select(UsernameClaim)
        .where(
            UsernameClaim.registration_attempt_id == registration_attempt_id,
            UsernameClaim.claim_type == "reservation",
        )
        .with_for_update()
    )

    if username_claim is not None:
        username_claim_expired = (
            username_claim.claim_type == "reservation"
            and username_claim.expires_at is not None
            and username_claim.expires_at <= db_now
        )

        if not username_claim_expired:
            raise UsernameUnavailableError

    if attempt_claim is not None:
        attempt_claim_expired = (
            attempt_claim.expires_at is not None
            and attempt_claim.expires_at <= db_now
        )

        if not attempt_claim_expired:
            raise UsernameReservationExistsError

    # The two lookups may identify the same expired reservation.
    expired_claim_ids = {
        claim.id
        for claim in (username_claim, attempt_claim)
        if claim is not None
    }

    if expired_claim_ids:
        expired_claims = session.scalars(
            select(UsernameClaim)
            .where(UsernameClaim.id.in_(expired_claim_ids))
            .with_for_update()
        ).all()

        for claim in expired_claims:
            session.delete(claim)

        session.flush()

    reservation_token = generate_reservation_token()
    expires_at = db_now + RESERVATION_LIFETIME

    reservation = UsernameClaim(
        username=username,
        claim_type="reservation",
        registration_attempt_id=registration_attempt_id,
        token_hash=hash_reservation_token(reservation_token),
        expires_at=expires_at,
    )

    session.add(reservation)
    session.flush()

    return CreatedUsernameReservation(
        reservation_id=reservation.id,
        username=reservation.username,
        reservation_token=reservation_token,
        expires_at=reservation.expires_at,
    )


_DUMMY_TOKEN = "A" * 43
_DUMMY_TOKEN_HASH = "0" * 64


class UsernameReservationInvalidError(Exception):
    """The reservation ID, attempt ID, or token does not match an active reservation."""


class UsernameReservationExpiredError(Exception):
    """The credentials match a reservation that has already expired."""


def release_username_reservation(
    session: Session,
    reservation_id: uuid.UUID,
    registration_attempt_id: uuid.UUID,
    reservation_token: str,
) -> None:
    """Delete a matching reservation inside the caller's transaction.

    Only the registration-attempt advisory lock is taken, using the same key as
    creation. Release never waits for a second advisory lock while holding one,
    so it cannot deadlock with creation's sorted two-lock order.

    The caller is responsible for committing or rolling back the transaction.
    """
    attempt_lock_key = f"relaysphere:registration-attempt:{registration_attempt_id}"
    session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(attempt_lock_key, 0))))

    db_now = session.scalar(select(func.clock_timestamp()))
    if db_now is None:
        raise RuntimeError("Database clock is unavailable.")

    claim = session.scalar(
        select(UsernameClaim)
        .where(
            UsernameClaim.id == reservation_id,
            UsernameClaim.claim_type == "reservation",
            UsernameClaim.registration_attempt_id == registration_attempt_id,
        )
        .with_for_update()
    )

    stored_hash = claim.token_hash if claim is not None and claim.token_hash else _DUMMY_TOKEN_HASH
    token_matches = verify_reservation_token(reservation_token, stored_hash)

    if claim is None or not token_matches:
        raise UsernameReservationInvalidError

    if claim.expires_at is None or claim.expires_at <= db_now:
        raise UsernameReservationExpiredError

    session.delete(claim)
    session.flush()
