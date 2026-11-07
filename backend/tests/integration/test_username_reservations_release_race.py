"""Race tests: releasing a reservation while another attempt creates the same username.

These tests use independent sessions that really commit, so ordinary rollback
isolation does not apply. Every row they create is removed by the claim_tracker
fixture, which targets only generated usernames and registration attempt IDs and
can never match the seeded reserved names.

Both outcomes below are valid, depending on which transaction takes the row lock
first:
- create runs after the release commits: create succeeds under the new attempt.
- create locks the old reservation first: create reports the name unavailable,
  then the release deletes the row and the name ends up free.
"""

import threading
import uuid
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import pytest
from sqlalchemy import Engine, delete, func, or_, select
from sqlalchemy.orm import Session

from app.models.username_claim import UsernameClaim
from app.services.username_reservations import (
    UsernameUnavailableError,
    create_username_reservation,
    release_username_reservation,
)

ROUNDS = 10
BARRIER_TIMEOUT_SECONDS = 15
RESULT_TIMEOUT_SECONDS = 30


@dataclass
class ClaimTracker:
    usernames: set[str] = field(default_factory=set)
    attempt_ids: set[uuid.UUID] = field(default_factory=set)

    def new_username(self) -> str:
        value = f"rel_{uuid.uuid4().hex[:8]}"
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
        if tracker.usernames or tracker.attempt_ids:
            with Session(bind=integration_test_engine) as cleanup_session:
                with cleanup_session.begin():
                    cleanup_session.execute(
                        delete(UsernameClaim).where(
                            or_(
                                UsernameClaim.username.in_(tracker.usernames),
                                UsernameClaim.registration_attempt_id.in_(tracker.attempt_ids),
                            )
                        )
                    )


def _release_worker(
    engine: Engine,
    barrier: threading.Barrier,
    reservation_id: uuid.UUID,
    attempt_id: uuid.UUID,
    token: str,
) -> str:
    session = Session(bind=engine, autoflush=False, expire_on_commit=False)

    try:
        barrier.wait()

        try:
            release_username_reservation(session, reservation_id, attempt_id, token)
            session.commit()
        except Exception:
            session.rollback()
            raise

        return "released"
    finally:
        session.close()


def _create_worker(
    engine: Engine,
    barrier: threading.Barrier,
    username: str,
    attempt_id: uuid.UUID,
) -> str:
    session = Session(bind=engine, autoflush=False, expire_on_commit=False)

    try:
        barrier.wait()

        try:
            create_username_reservation(session, username, attempt_id)
            session.commit()
        except UsernameUnavailableError:
            session.rollback()
            return "unavailable"
        except Exception:
            session.rollback()
            raise

        return "created"
    finally:
        session.close()


def _count(engine: Engine, *conditions: object) -> int:
    with Session(bind=engine) as session:
        statement = select(func.count()).select_from(UsernameClaim).where(*conditions)
        return session.scalar(statement) or 0


@pytest.mark.parametrize("round_number", range(ROUNDS))
def test_release_racing_with_create_for_the_same_username(
    integration_test_engine: Engine,
    claim_tracker: ClaimTracker,
    round_number: int,
) -> None:
    username = claim_tracker.new_username()
    old_attempt = claim_tracker.new_attempt_id()
    new_attempt = claim_tracker.new_attempt_id()

    with Session(bind=integration_test_engine, expire_on_commit=False) as setup_session:
        with setup_session.begin():
            created = create_username_reservation(setup_session, username, old_attempt)

    barrier = threading.Barrier(2, timeout=BARRIER_TIMEOUT_SECONDS)

    with ThreadPoolExecutor(max_workers=2) as pool:
        release_future = pool.submit(
            _release_worker,
            integration_test_engine,
            barrier,
            created.reservation_id,
            old_attempt,
            created.reservation_token,
        )
        create_future = pool.submit(
            _create_worker,
            integration_test_engine,
            barrier,
            username,
            new_attempt,
        )
        release_result = release_future.result(timeout=RESULT_TIMEOUT_SECONDS)
        create_result = create_future.result(timeout=RESULT_TIMEOUT_SECONDS)

    print(f"round {round_number}: release={release_result} create={create_result}")

    assert release_result == "released"
    assert create_result in {"created", "unavailable"}

    # The old reservation is always gone after a successful release.
    assert _count(integration_test_engine, UsernameClaim.id == created.reservation_id) == 0
    assert (
        _count(
            integration_test_engine,
            UsernameClaim.registration_attempt_id == old_attempt,
        )
        == 0
    )

    if create_result == "created":
        assert _count(integration_test_engine, UsernameClaim.username == username) == 1
        assert (
            _count(
                integration_test_engine,
                UsernameClaim.username == username,
                UsernameClaim.claim_type == "reservation",
                UsernameClaim.registration_attempt_id == new_attempt,
            )
            == 1
        )
    else:
        assert _count(integration_test_engine, UsernameClaim.username == username) == 0
        assert (
            _count(
                integration_test_engine,
                UsernameClaim.registration_attempt_id == new_attempt,
            )
            == 0
        )
