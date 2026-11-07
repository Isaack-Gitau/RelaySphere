import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.username_claim import UsernameClaim
from app.security.username_reservations import verify_reservation_token
from app.services.username_reservations import (
    UsernameReservationExistsError,
    UsernameUnavailableError,
    create_username_reservation,
)


def test_create_username_reservation_persists_hashed_token_and_five_minute_expiry(
    db_session: Session,
) -> None:
    before = db_session.scalar(select(func.clock_timestamp()))
    assert before is not None

    attempt_id = uuid.uuid4()
    created = create_username_reservation(
        db_session,
        "mira_njoroge",
        attempt_id,
    )

    after = db_session.scalar(select(func.clock_timestamp()))
    assert after is not None

    stored = db_session.get(UsernameClaim, created.reservation_id)
    assert stored is not None
    assert stored.username == "mira_njoroge"
    assert stored.claim_type == "reservation"
    assert stored.registration_attempt_id == attempt_id
    assert stored.token_hash is not None
    assert stored.token_hash != created.reservation_token
    assert verify_reservation_token(created.reservation_token, stored.token_hash)

    assert created.expires_at > before + timedelta(minutes=4, seconds=59)
    assert created.expires_at <= after + timedelta(minutes=5)


def test_create_username_reservation_rejects_reserved_username(
    db_session: Session,
) -> None:
    with pytest.raises(UsernameUnavailableError):
        create_username_reservation(
            db_session,
            "admin",
            uuid.uuid4(),
        )


def test_create_username_reservation_rejects_permanently_claimed_username(
    db_session: Session,
) -> None:
    user = User(
        email=f"reservation-owner-{uuid.uuid4().hex}@example.com",
        display_name="Reservation Owner",
        password_hash=None,
        is_active=True,
        email_verified_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.flush()

    db_session.add(
        UsernameClaim(
            username="claimed_username",
            claim_type="permanent",
            user_id=user.id,
        )
    )
    db_session.flush()

    with pytest.raises(UsernameUnavailableError):
        create_username_reservation(
            db_session,
            "claimed_username",
            uuid.uuid4(),
        )


def test_create_username_reservation_rejects_active_username_reservation(
    db_session: Session,
) -> None:
    db_session.add(
        UsernameClaim(
            username="active_username",
            claim_type="reservation",
            registration_attempt_id=uuid.uuid4(),
            token_hash="a" * 64,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    db_session.flush()

    with pytest.raises(UsernameUnavailableError):
        create_username_reservation(
            db_session,
            "active_username",
            uuid.uuid4(),
        )


def test_create_username_reservation_rejects_attempt_with_active_reservation(
    db_session: Session,
) -> None:
    attempt_id = uuid.uuid4()
    db_session.add(
        UsernameClaim(
            username="another_username",
            claim_type="reservation",
            registration_attempt_id=attempt_id,
            token_hash="b" * 64,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    db_session.flush()

    with pytest.raises(UsernameReservationExistsError):
        create_username_reservation(
            db_session,
            "new_username",
            attempt_id,
        )


def test_create_username_reservation_reclaims_expired_reservation(
    db_session: Session,
) -> None:
    attempt_id = uuid.uuid4()
    expired_claim = UsernameClaim(
        username="expired_username",
        claim_type="reservation",
        registration_attempt_id=attempt_id,
        token_hash="c" * 64,
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    db_session.add(expired_claim)
    db_session.flush()
    expired_id = expired_claim.id

    created = create_username_reservation(
        db_session,
        "expired_username",
        attempt_id,
    )

    assert created.reservation_id != expired_id
    assert db_session.get(UsernameClaim, expired_id) is None

    replacement = db_session.get(UsernameClaim, created.reservation_id)
    assert replacement is not None
    assert replacement.username == "expired_username"
    assert replacement.registration_attempt_id == attempt_id


def test_create_username_reservation_reclaims_expired_attempt_on_another_username(
    db_session: Session,
) -> None:
    attempt_id = uuid.uuid4()
    expired_claim = UsernameClaim(
        username="old_username",
        claim_type="reservation",
        registration_attempt_id=attempt_id,
        token_hash="d" * 64,
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    db_session.add(expired_claim)
    db_session.flush()
    expired_id = expired_claim.id

    created = create_username_reservation(
        db_session,
        "replacement_username",
        attempt_id,
    )

    assert created.reservation_id != expired_id
    assert db_session.get(UsernameClaim, expired_id) is None

    replacement = db_session.get(UsernameClaim, created.reservation_id)
    assert replacement is not None
    assert replacement.username == "replacement_username"
    assert replacement.registration_attempt_id == attempt_id
