import threading
import uuid
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, delete, text
from sqlalchemy.orm import Session, sessionmaker

from app.models.email_outbox import EmailOutbox
from app.services.email_outbox import claim_email_jobs

LOCK_TIMEOUT_SQL = text("SET LOCAL lock_timeout = '2s'")


def _clear_outbox(factory: sessionmaker[Session]) -> None:
    with factory.begin() as session:
        session.execute(delete(EmailOutbox))


@pytest.fixture
def session_factory(
    integration_test_engine: Engine,
) -> Generator[sessionmaker[Session]]:
    """Provide independent committed sessions on the dedicated test database.

    These tests commit real rows, so the outbox table is emptied before and
    after each test. The engine fixture guarantees this is relaysphere_test.
    """
    factory = sessionmaker(
        bind=integration_test_engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )

    _clear_outbox(factory)

    try:
        yield factory
    finally:
        _clear_outbox(factory)


def _future_now() -> datetime:
    return datetime.now(UTC) + timedelta(seconds=5)


def _insert_jobs(
    factory: sessionmaker[Session],
    count: int,
    *,
    status: str = "pending",
    attempt_count: int = 0,
    locked_until: datetime | None = None,
) -> list[uuid.UUID]:
    jobs = [
        EmailOutbox(
            event_type="email.verification",
            encrypted_payload=b"concurrency-test-payload",
            status=status,
            attempt_count=attempt_count,
            locked_until=locked_until,
            lock_token=uuid.uuid4() if status == "processing" else None,
        )
        for _ in range(count)
    ]

    with factory.begin() as session:
        session.add_all(jobs)
        session.flush()
        return [job.id for job in jobs]


def _load(factory: sessionmaker[Session], job_id: uuid.UUID) -> EmailOutbox:
    with factory() as session:
        job = session.get(EmailOutbox, job_id)
        assert job is not None
        return job


def test_concurrent_claims_never_return_the_same_job(
    session_factory: sessionmaker[Session],
) -> None:
    job_ids = set(_insert_jobs(session_factory, 3))
    now = _future_now()

    with session_factory() as session_a, session_factory() as session_b:
        session_b.execute(LOCK_TIMEOUT_SQL)

        claimed_a = claim_email_jobs(session_a, batch_size=2, now=now)
        # Session A has not committed, so it still holds its row locks.
        claimed_b = claim_email_jobs(session_b, batch_size=10, now=now)

        ids_a = {job.id for job in claimed_a}
        ids_b = {job.id for job in claimed_b}

        assert len(ids_a) == 2
        assert len(ids_b) == 1
        assert ids_a.isdisjoint(ids_b)
        assert ids_a | ids_b == job_ids

        session_a.commit()
        session_b.commit()

    loaded = [_load(session_factory, job_id) for job_id in job_ids]

    assert all(job.status == "processing" for job in loaded)
    assert all(job.attempt_count == 1 for job in loaded)
    assert len({job.lock_token for job in loaded}) == 3


def test_rolled_back_claim_releases_the_job_to_other_workers(
    session_factory: sessionmaker[Session],
) -> None:
    (job_id,) = _insert_jobs(session_factory, 1)
    now = _future_now()

    with session_factory() as session_a, session_factory() as session_b:
        session_b.execute(LOCK_TIMEOUT_SQL)

        claimed_a = claim_email_jobs(session_a, now=now)
        assert [job.id for job in claimed_a] == [job_id]

        assert claim_email_jobs(session_b, now=now) == []

        session_a.rollback()

        reclaimed = claim_email_jobs(session_b, now=now)
        assert [job.id for job in reclaimed] == [job_id]
        assert reclaimed[0].attempt_count == 1

        session_b.commit()

    job = _load(session_factory, job_id)

    assert job.status == "processing"
    assert job.attempt_count == 1


def test_exhausted_job_held_by_another_worker_does_not_block_healthy_jobs(
    session_factory: sessionmaker[Session],
) -> None:
    expired = datetime.now(UTC) - timedelta(minutes=5)
    (exhausted_id,) = _insert_jobs(
        session_factory,
        1,
        status="processing",
        attempt_count=8,
        locked_until=expired,
    )
    now = _future_now()

    with session_factory() as session_a, session_factory() as session_b:
        session_b.execute(LOCK_TIMEOUT_SQL)

        # Worker A fails the exhausted job but has not committed yet.
        assert claim_email_jobs(session_a, batch_size=1, now=now) == []

        (healthy_id,) = _insert_jobs(session_factory, 1)

        claimed_b = claim_email_jobs(session_b, batch_size=1, now=now)

        assert [job.id for job in claimed_b] == [healthy_id]

        session_a.commit()
        session_b.commit()

    exhausted = _load(session_factory, exhausted_id)
    healthy = _load(session_factory, healthy_id)

    assert exhausted.status == "failed"
    assert exhausted.attempt_count == 8
    assert exhausted.encrypted_payload is None
    assert exhausted.lock_token is None
    assert exhausted.last_error_code == "email_delivery_attempts_exhausted"
    assert healthy.status == "processing"
    assert healthy.attempt_count == 1


def test_parallel_workers_claim_each_job_exactly_once(
    session_factory: sessionmaker[Session],
) -> None:
    healthy_count = 24
    exhausted_count = 4
    worker_count = 4

    expired = datetime.now(UTC) - timedelta(minutes=5)
    exhausted_ids = _insert_jobs(
        session_factory,
        exhausted_count,
        status="processing",
        attempt_count=8,
        locked_until=expired,
    )
    healthy_ids = set(_insert_jobs(session_factory, healthy_count))
    now = _future_now()
    start_barrier = threading.Barrier(worker_count)

    def run_worker() -> list[uuid.UUID]:
        claimed_ids: list[uuid.UUID] = []
        start_barrier.wait(timeout=10)

        while True:
            with session_factory() as session:
                session.execute(LOCK_TIMEOUT_SQL)
                jobs = claim_email_jobs(session, batch_size=1, now=now)
                claimed_ids.extend(job.id for job in jobs)
                session.commit()

            if not jobs:
                return claimed_ids

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(run_worker) for _ in range(worker_count)]
        results = [future.result(timeout=60) for future in futures]

    all_claimed = [job_id for ids in results for job_id in ids]

    assert len(all_claimed) == healthy_count
    assert set(all_claimed) == healthy_ids

    for job_id in healthy_ids:
        job = _load(session_factory, job_id)
        assert job.status == "processing"
        assert job.attempt_count == 1

    for job_id in exhausted_ids:
        job = _load(session_factory, job_id)
        assert job.status == "failed"
        assert job.attempt_count == 8
        assert job.encrypted_payload is None
        assert job.last_error_code == "email_delivery_attempts_exhausted"
