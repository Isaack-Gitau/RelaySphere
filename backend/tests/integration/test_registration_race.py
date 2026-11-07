"""Real-commit tests for registration and username reservations.

These tests use independent sessions that really commit, so ordinary rollback
isolation does not apply. The claim_tracker fixture removes only the users, claims
and outbox rows these tests generated. Deleting a user cascades to its claim and
verification tokens.
"""

import threading
import uuid
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import pytest
from sqlalchemy import Engine, delete, func, or_, select
from sqlalchemy.orm import Session

from app.models.email_outbox import EmailOutbox
from app.models.user import User
from app.models.username_claim import UsernameClaim
from app.schemas.auth import RegisterRequest
from app.services import registration as registration_service
from app.services.registration import register_user_with_verification_token
from app.services.username_reservations import (
    UsernameReservationExpiredError,
    UsernameReservationInvalidError,
    create_username_reservation,
)

ROUNDS = 10
BARRIER_TIMEOUT_SECONDS = 30
RESULT_TIMEOUT_SECONDS = 60


@dataclass
class ClaimTracker:
    emails: set[str] = field(default_factory=set)
    usernames: set[str] = field(default_factory=set)
    attempt_ids: set[uuid.UUID] = field(default_factory=set)
    outbox_ids: set[uuid.UUID] = field(default_factory=set)

    def new_email(self) -> str:
        value = f"race-{uuid.uuid4().hex[:12]}@example.com"
        self.emails.add(value)
        return value

    def new_username(self) -> str:
        value = f"reg_{uuid.uuid4().hex[:8]}"
        self.usernames.add(value)
        return value

    def new_attempt_id(self) -> uuid.UUID:
        value = uuid.uuid4()
        self.attempt_ids.add(value)
        return value


@pytest.fixture
def claim_tracker(integration_test_engine: Engine) -> Generator[ClaimTracker]:
    tracker = ClaimTracker()

    try:
        yield tracker
    finally:
        with Session(bind=integration_test_engine) as cleanup_session:
            with cleanup_session.begin():
                if tracker.emails:
                    cleanup_session.execute(delete(User).where(User.email.in_(tracker.emails)))
                if tracker.usernames or tracker.attempt_ids:
                    cleanup_session.execute(
                        delete(UsernameClaim).where(
                            or_(
                                UsernameClaim.username.in_(tracker.usernames),
                                UsernameClaim.registration_attempt_id.in_(tracker.attempt_ids),
                            )
                        )
                    )
                if tracker.outbox_ids:
                    cleanup_session.execute(
                        delete(EmailOutbox).where(EmailOutbox.id.in_(tracker.outbox_ids))
                    )


@pytest.fixture
def recorded_outbox(
    claim_tracker: ClaimTracker,
    configured_outbox_encryption: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Record outbox rows created by registration so cleanup can remove only those."""
    real_enqueue = registration_service.enqueue_email

    def recording_enqueue(session: Session, event_type: str, payload: dict[str, object]):
        record = real_enqueue(session, event_type, payload)
        claim_tracker.outbox_ids.add(record.id)
        return record

    monkeypatch.setattr(registration_service, "enqueue_email", recording_enqueue)


def _reserve(engine: Engine, tracker: ClaimTracker, email: str) -> RegisterRequest:
    username = tracker.new_username()
    attempt_id = tracker.new_attempt_id()

    with Session(bind=engine, expire_on_commit=False) as setup_session:
        with setup_session.begin():
            created = create_username_reservation(setup_session, username, attempt_id)

    return RegisterRequest(
        email=email,
        display_name="Race Test",
        password="a-strong-test-password",
        username=created.username,
        reservation_id=created.reservation_id,
        registration_attempt_id=attempt_id,
        reservation_token=created.reservation_token,
    )


def _register_worker(
    engine: Engine,
    barrier: threading.Barrier,
    registration: RegisterRequest,
) -> str:
    session = Session(bind=engine, autoflush=False, expire_on_commit=False)

    try:
        barrier.wait()

        try:
            register_user_with_verification_token(session, registration)
            session.commit()
        except (UsernameReservationInvalidError, UsernameReservationExpiredError) as exc:
            session.rollback()
            return type(exc).__name__
        except Exception:
            session.rollback()
            raise

        return "registered"
    finally:
        session.close()


def _count(engine: Engine, model: type, *conditions: object) -> int:
    with Session(bind=engine) as session:
        statement = select(func.count()).select_from(model).where(*conditions)
        return session.scalar(statement) or 0


@pytest.mark.parametrize("round_number", range(ROUNDS))
def test_two_registrations_on_one_reservation_have_exactly_one_winner(
    integration_test_engine: Engine,
    claim_tracker: ClaimTracker,
    recorded_outbox: None,
    round_number: int,
) -> None:
    first_email = claim_tracker.new_email()
    second_email = claim_tracker.new_email()
    first = _reserve(integration_test_engine, claim_tracker, first_email)
    second = first.model_copy(update={"email": second_email})

    barrier = threading.Barrier(2, timeout=BARRIER_TIMEOUT_SECONDS)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_register_worker, integration_test_engine, barrier, registration)
            for registration in (first, second)
        ]
        results = [future.result(timeout=RESULT_TIMEOUT_SECONDS) for future in futures]

    print(f"round {round_number}: {results}")

    assert sorted(results) == ["UsernameReservationInvalidError", "registered"]
    assert _count(integration_test_engine, User, User.email.in_([first_email, second_email])) == 1
    assert (
        _count(integration_test_engine, UsernameClaim, UsernameClaim.username == first.username)
        == 1
    )
    assert (
        _count(
            integration_test_engine,
            UsernameClaim,
            UsernameClaim.username == first.username,
            UsernameClaim.claim_type == "permanent",
            UsernameClaim.user_id.is_not(None),
        )
        == 1
    )


def test_failed_registration_leaves_the_committed_reservation_intact(
    integration_test_engine: Engine,
    claim_tracker: ClaimTracker,
    configured_outbox_encryption: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email = claim_tracker.new_email()
    registration = _reserve(integration_test_engine, claim_tracker, email)

    def fail_enqueue(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Simulated email enqueue failure")

    monkeypatch.setattr(registration_service, "enqueue_email", fail_enqueue)

    session = Session(bind=integration_test_engine, autoflush=False, expire_on_commit=False)
    try:
        with pytest.raises(RuntimeError, match="Simulated email enqueue failure"):
            register_user_with_verification_token(session, registration)
        session.rollback()
    finally:
        session.close()

    assert _count(integration_test_engine, User, User.email == email) == 0
    assert (
        _count(
            integration_test_engine,
            UsernameClaim,
            UsernameClaim.username == registration.username,
            UsernameClaim.claim_type == "reservation",
            UsernameClaim.user_id.is_(None),
        )
        == 1
    )
    assert (
        _count(
            integration_test_engine,
            UsernameClaim,
            UsernameClaim.username == registration.username,
            UsernameClaim.claim_type == "permanent",
        )
        == 0
    )
