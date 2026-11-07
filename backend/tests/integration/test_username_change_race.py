"""Concurrency acceptance tests for username changes.

These tests use independent sessions that really commit, so ordinary rollback
isolation does not apply. Every row they create is removed by the tracker fixture,
which targets only generated usernames and user IDs and can never match the seeded
reserved names.
"""

import threading
import uuid
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, delete, or_, select
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.username_claim import UsernameClaim
from app.services.username_change import UsernameChangeCooldownError, change_username
from app.services.username_reservations import UsernameUnavailableError

ROUNDS = 10
BARRIER_TIMEOUT_SECONDS = 15
RESULT_TIMEOUT_SECONDS = 30
_PAST_COOLDOWN = timedelta(days=31)


@dataclass
class Tracker:
    usernames: set[str] = field(default_factory=set)
    user_ids: set[uuid.UUID] = field(default_factory=set)

    def new_username(self) -> str:
        value = f"rchg_{uuid.uuid4().hex[:8]}"
        self.usernames.add(value)
        return value


@pytest.fixture
def tracker(integration_test_engine: Engine) -> Generator[Tracker]:
    created = Tracker()

    try:
        yield created
    finally:
        if created.usernames or created.user_ids:
            with Session(bind=integration_test_engine) as cleanup_session:
                with cleanup_session.begin():
                    cleanup_session.execute(
                        delete(UsernameClaim).where(
                            or_(
                                UsernameClaim.username.in_(created.usernames),
                                UsernameClaim.user_id.in_(created.user_ids),
                            )
                        )
                    )
                    cleanup_session.execute(delete(User).where(User.id.in_(created.user_ids)))


def _create_user(
    engine: Engine,
    tracker: Tracker,
    username: str,
    claim_age: timedelta = _PAST_COOLDOWN,
) -> uuid.UUID:
    with Session(bind=engine) as session:
        with session.begin():
            user = User(
                email=f"race-{uuid.uuid4().hex}@example.com",
                display_name="Username Change Race",
                password_hash=None,
                is_active=True,
                email_verified_at=datetime.now(UTC),
            )
            session.add(user)
            session.flush()
            user_id = user.id
            tracker.user_ids.add(user_id)
            session.add(
                UsernameClaim(
                    username=username,
                    claim_type="permanent",
                    user_id=user_id,
                    created_at=datetime.now(UTC) - claim_age,
                )
            )

    return user_id


def _worker(
    engine: Engine,
    barrier: threading.Barrier,
    user_id: uuid.UUID,
    new_username: str,
) -> str:
    session = Session(bind=engine, autoflush=False, expire_on_commit=False)

    try:
        barrier.wait()

        try:
            changed = change_username(session, user_id, new_username)
            session.commit()
        except (UsernameUnavailableError, UsernameChangeCooldownError) as exc:
            session.rollback()
            return type(exc).__name__
        except Exception:
            session.rollback()
            raise

        return "changed" if changed else "unchanged"
    finally:
        session.close()


def _race(engine: Engine, requests: list[tuple[uuid.UUID, str]]) -> list[str]:
    barrier = threading.Barrier(len(requests), timeout=BARRIER_TIMEOUT_SECONDS)

    with ThreadPoolExecutor(max_workers=len(requests)) as pool:
        futures = [
            pool.submit(_worker, engine, barrier, user_id, new_username)
            for user_id, new_username in requests
        ]
        return [future.result(timeout=RESULT_TIMEOUT_SECONDS) for future in futures]


def _claim_rows(engine: Engine, username: str) -> list[tuple[str, uuid.UUID | None]]:
    with Session(bind=engine) as session:
        rows = session.execute(
            select(UsernameClaim.claim_type, UsernameClaim.user_id).where(
                UsernameClaim.username == username
            )
        ).all()

    return [(row.claim_type, row.user_id) for row in rows]


def _permanent_usernames(engine: Engine, user_id: uuid.UUID) -> list[str]:
    with Session(bind=engine) as session:
        return list(
            session.scalars(
                select(UsernameClaim.username).where(
                    UsernameClaim.user_id == user_id,
                    UsernameClaim.claim_type == "permanent",
                )
            ).all()
        )


@pytest.mark.parametrize("round_number", range(ROUNDS))
def test_two_users_racing_for_one_free_name_have_exactly_one_winner(
    integration_test_engine: Engine,
    tracker: Tracker,
    round_number: int,
) -> None:
    old_a = tracker.new_username()
    old_b = tracker.new_username()
    target = tracker.new_username()
    user_a = _create_user(integration_test_engine, tracker, old_a)
    user_b = _create_user(integration_test_engine, tracker, old_b)

    results = _race(integration_test_engine, [(user_a, target), (user_b, target)])

    assert sorted(results) == ["UsernameUnavailableError", "changed"]
    held_by = {
        user_id: _permanent_usernames(integration_test_engine, user_id)
        for user_id in (user_a, user_b)
    }
    winners = [user_id for user_id, names in held_by.items() if names == [target]]
    losers = [user_id for user_id, names in held_by.items() if names != [target]]
    assert len(winners) == 1
    assert len(losers) == 1
    old_names = {user_a: old_a, user_b: old_b}
    assert _claim_rows(integration_test_engine, target) == [("permanent", winners[0])]
    assert held_by[losers[0]] == [old_names[losers[0]]]
    assert _claim_rows(integration_test_engine, old_names[winners[0]]) == [("reserved", None)]


@pytest.mark.parametrize("round_number", range(ROUNDS))
def test_two_users_swapping_names_fail_without_a_deadlock(
    integration_test_engine: Engine,
    tracker: Tracker,
    round_number: int,
) -> None:
    name_a = tracker.new_username()
    name_b = tracker.new_username()
    user_a = _create_user(integration_test_engine, tracker, name_a)
    user_b = _create_user(integration_test_engine, tracker, name_b)

    results = _race(integration_test_engine, [(user_a, name_b), (user_b, name_a)])

    assert results == ["UsernameUnavailableError", "UsernameUnavailableError"]
    assert _permanent_usernames(integration_test_engine, user_a) == [name_a]
    assert _permanent_usernames(integration_test_engine, user_b) == [name_b]


@pytest.mark.parametrize("round_number", range(ROUNDS))
def test_one_user_firing_two_different_changes_at_once_changes_only_once(
    integration_test_engine: Engine,
    tracker: Tracker,
    round_number: int,
) -> None:
    old_name = tracker.new_username()
    first = tracker.new_username()
    second = tracker.new_username()
    user_id = _create_user(integration_test_engine, tracker, old_name)

    results = _race(integration_test_engine, [(user_id, first), (user_id, second)])

    assert sorted(results) == ["UsernameChangeCooldownError", "changed"]
    held = _permanent_usernames(integration_test_engine, user_id)
    assert len(held) == 1
    assert held[0] in {first, second}
    loser_name = ({first, second} - {held[0]}).pop()
    assert _claim_rows(integration_test_engine, old_name) == [("reserved", None)]
    assert _claim_rows(integration_test_engine, loser_name) == []


@pytest.mark.parametrize("round_number", range(ROUNDS))
def test_the_same_change_submitted_twice_at_once_is_idempotent(
    integration_test_engine: Engine,
    tracker: Tracker,
    round_number: int,
) -> None:
    old_name = tracker.new_username()
    target = tracker.new_username()
    user_id = _create_user(integration_test_engine, tracker, old_name)

    results = _race(integration_test_engine, [(user_id, target), (user_id, target)])

    assert sorted(results) == ["changed", "unchanged"]
    assert _permanent_usernames(integration_test_engine, user_id) == [target]
    assert _claim_rows(integration_test_engine, old_name) == [("reserved", None)]
    assert _claim_rows(integration_test_engine, target) == [("permanent", user_id)]
