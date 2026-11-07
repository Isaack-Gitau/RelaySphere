"""Concurrency acceptance tests for username reservations.

These tests use independent sessions that really commit, so ordinary
rollback isolation does not apply. Every row they create is removed by
the claim_tracker fixture, which targets only generated usernames and
registration attempt IDs and can never match the seeded reserved names.
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
    UsernameReservationExistsError,
    UsernameUnavailableError,
    create_username_reservation,
)

ROUNDS = 10
BARRIER_TIMEOUT_SECONDS = 15
RESULT_TIMEOUT_SECONDS = 30


@dataclass
class ClaimTracker:
    usernames: set[uuid.UUID | str] = field(default_factory=set)
    attempt_ids: set[uuid.UUID] = field(default_factory=set)

    def new_username(self) -> str:
        value = f"race_{uuid.uuid4().hex[:8]}"
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


def _worker(
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
        except (UsernameUnavailableError, UsernameReservationExistsError) as exc:
            session.rollback()
            return type(exc).__name__
        except Exception:
            session.rollback()
            raise

        return "created"
    finally:
        session.close()


def _race(engine: Engine, requests: list[tuple[str, uuid.UUID]]) -> list[str]:
    barrier = threading.Barrier(len(requests), timeout=BARRIER_TIMEOUT_SECONDS)

    with ThreadPoolExecutor(max_workers=len(requests)) as pool:
        futures = [
            pool.submit(_worker, engine, barrier, username, attempt_id)
            for username, attempt_id in requests
        ]
        return [future.result(timeout=RESULT_TIMEOUT_SECONDS) for future in futures]


def _count(engine: Engine, *conditions: object) -> int:
    with Session(bind=engine) as session:
        statement = select(func.count()).select_from(UsernameClaim).where(*conditions)
        return session.scalar(statement) or 0


@pytest.mark.parametrize("round_number", range(ROUNDS))
def test_same_username_with_different_attempts_has_exactly_one_winner(
    integration_test_engine: Engine,
    claim_tracker: ClaimTracker,
    round_number: int,
) -> None:
    username = claim_tracker.new_username()
    attempts = [claim_tracker.new_attempt_id(), claim_tracker.new_attempt_id()]

    results = _race(integration_test_engine, [(username, attempt) for attempt in attempts])

    assert sorted(results) == ["UsernameUnavailableError", "created"]
    assert _count(integration_test_engine, UsernameClaim.username == username) == 1
    assert (
        _count(
            integration_test_engine,
            UsernameClaim.username == username,
            UsernameClaim.claim_type == "reservation",
            UsernameClaim.registration_attempt_id.in_(attempts),
        )
        == 1
    )


@pytest.mark.parametrize("round_number", range(ROUNDS))
def test_same_attempt_with_different_usernames_has_exactly_one_winner(
    integration_test_engine: Engine,
    claim_tracker: ClaimTracker,
    round_number: int,
) -> None:
    usernames = [claim_tracker.new_username(), claim_tracker.new_username()]
    attempt_id = claim_tracker.new_attempt_id()

    results = _race(integration_test_engine, [(username, attempt_id) for username in usernames])

    assert sorted(results) == ["UsernameReservationExistsError", "created"]
    assert (
        _count(
            integration_test_engine,
            UsernameClaim.registration_attempt_id == attempt_id,
            UsernameClaim.claim_type == "reservation",
        )
        == 1
    )
    assert _count(integration_test_engine, UsernameClaim.username.in_(usernames)) == 1
