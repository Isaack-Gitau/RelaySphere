from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.rate_limit_counter import RateLimitCounter
from app.security.rate_limit import hash_rate_limit_identifier
from app.services.rate_limiting import (
    RateLimitBucket,
    consume_rate_limit_buckets,
)


def make_session_factory(engine) -> sessionmaker[Session]:
    """Create independent sessions for committed rate-limit operations."""
    return sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )


def test_rate_limit_counter_commits_independently_of_other_transactions(
    integration_test_engine,
) -> None:
    factory = make_session_factory(integration_test_engine)
    identifier = f"rate-limit-{uuid4()}@example.com"
    now = datetime(2026, 10, 31, 10, 0, tzinfo=UTC)

    bucket = RateLimitBucket(
        scope="integration-independent-commit",
        kind="email",
        identifier=identifier,
        limit=2,
        window_seconds=900,
    )

    # Consume the allowed requests.
    assert consume_rate_limit_buckets([bucket], now=now, session_factory=factory).allowed
    assert consume_rate_limit_buckets([bucket], now=now, session_factory=factory).allowed

    # The third request must be denied.
    denied = consume_rate_limit_buckets([bucket], now=now, session_factory=factory)
    assert denied.allowed is False
    assert denied.retry_after_seconds is not None
    assert 1 <= denied.retry_after_seconds <= 900

    key_hash = hash_rate_limit_identifier("email", identifier)

    # Read through a fresh session to prove the limiter committed its writes.
    with factory() as session:
        counter = session.scalar(
            select(RateLimitCounter).where(
                RateLimitCounter.scope == bucket.scope,
                RateLimitCounter.key_hash == key_hash,
            )
        )

        assert counter is not None
        assert counter.count == 3


def test_all_buckets_are_incremented_even_when_one_limit_is_exceeded(
    integration_test_engine,
) -> None:
    factory = make_session_factory(integration_test_engine)
    identifier = f"rate-limit-{uuid4()}@example.com"
    now = datetime(2026, 10, 31, 11, 0, tzinfo=UTC)

    restrictive_bucket = RateLimitBucket(
        scope="integration-restrictive",
        kind="email",
        identifier=identifier,
        limit=1,
        window_seconds=900,
    )
    broader_bucket = RateLimitBucket(
        scope="integration-broader",
        kind="email",
        identifier=identifier,
        limit=5,
        window_seconds=900,
    )

    # First request is allowed.
    assert consume_rate_limit_buckets(
        [restrictive_bucket, broader_bucket],
        now=now,
        session_factory=factory,
    ).allowed

    # Second request exceeds the restrictive bucket, but both counters
    # must still be incremented.
    result = consume_rate_limit_buckets(
        [restrictive_bucket, broader_bucket],
        now=now,
        session_factory=factory,
    )
    assert result.allowed is False

    restrictive_hash = hash_rate_limit_identifier("email", identifier)

    with factory() as session:
        restrictive_count = session.scalar(
            select(RateLimitCounter.count).where(
                RateLimitCounter.scope == restrictive_bucket.scope,
                RateLimitCounter.key_hash == restrictive_hash,
            )
        )
        broader_count = session.scalar(
            select(RateLimitCounter.count).where(
                RateLimitCounter.scope == broader_bucket.scope,
                RateLimitCounter.key_hash == restrictive_hash,
            )
        )

    assert restrictive_count == 2
    assert broader_count == 2


def test_concurrent_requests_do_not_lose_counter_increments(
    integration_test_engine,
) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    factory = make_session_factory(integration_test_engine)
    identifier = f"rate-limit-concurrent-{uuid4()}@example.com"
    now = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
    request_count = 12
    barrier = Barrier(request_count)

    bucket = RateLimitBucket(
        scope="integration-concurrent",
        kind="email",
        identifier=identifier,
        limit=request_count + 5,
        window_seconds=900,
    )

    def consume_request():
        barrier.wait(timeout=15)
        return consume_rate_limit_buckets(
            [bucket],
            now=now,
            session_factory=factory,
        )

    with ThreadPoolExecutor(max_workers=request_count) as executor:
        futures = [executor.submit(consume_request) for _ in range(request_count)]
        results = [future.result(timeout=30) for future in futures]

    assert all(result.allowed for result in results)

    key_hash = hash_rate_limit_identifier("email", identifier)

    with factory() as session:
        counter = session.scalar(
            select(RateLimitCounter).where(
                RateLimitCounter.scope == bucket.scope,
                RateLimitCounter.key_hash == key_hash,
            )
        )

    assert counter is not None
    assert counter.count == request_count
