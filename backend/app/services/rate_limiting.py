from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from math import ceil
from typing import Literal

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, sessionmaker

from app.db.session import get_session_factory
from app.models.rate_limit_counter import RateLimitCounter
from app.security.rate_limit import hash_rate_limit_identifier

IdentifierKind = Literal["ip", "email"]


@dataclass(frozen=True, slots=True)
class RateLimitBucket:
    """Describe one independently enforced rate-limit bucket."""

    scope: str
    kind: IdentifierKind
    identifier: str
    limit: int
    window_seconds: int


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    """Describe the outcome of consuming one or more buckets."""

    allowed: bool
    retry_after_seconds: int | None = None


def _window_start(now: datetime, window_seconds: int) -> datetime:
    """Return the UTC start of the fixed window containing the given time."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Rate-limit timestamps must be timezone-aware.")

    if window_seconds <= 0:
        raise ValueError("Rate-limit window must be greater than zero.")

    timestamp = int(now.timestamp())
    aligned_timestamp = timestamp - (timestamp % window_seconds)

    return datetime.fromtimestamp(aligned_timestamp, tz=UTC)


def consume_rate_limit_buckets(
    buckets: Sequence[RateLimitBucket],
    *,
    now: datetime | None = None,
    session_factory: sessionmaker[Session] | None = None,
) -> RateLimitResult:
    """
    Atomically consume all applicable buckets in an independent transaction.

    Every bucket is incremented, including buckets that exceed their limit.
    Database errors intentionally propagate to the HTTP layer.
    """
    if not buckets:
        raise ValueError("At least one rate-limit bucket is required.")

    current_time = now or datetime.now(UTC)

    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ValueError("Rate-limit timestamps must be timezone-aware.")

    prepared_buckets: list[tuple[RateLimitBucket, str, datetime]] = []

    for bucket in buckets:
        if not bucket.scope or len(bucket.scope) > 64:
            raise ValueError("Rate-limit scope must contain 1 to 64 characters.")

        if bucket.limit <= 0:
            raise ValueError("Rate-limit threshold must be greater than zero.")

        if bucket.window_seconds <= 0:
            raise ValueError("Rate-limit window must be greater than zero.")

        key_hash = hash_rate_limit_identifier(
            bucket.kind,
            bucket.identifier,
        )
        start = _window_start(current_time, bucket.window_seconds)

        prepared_buckets.append((bucket, key_hash, start))

    # Acquire counter-row locks in a consistent order across requests.
    prepared_buckets.sort(key=lambda item: (item[0].scope, item[1], item[2]))

    factory = session_factory or get_session_factory()
    retry_after_seconds = 0

    with factory() as session:
        with session.begin():
            for bucket, key_hash, start in prepared_buckets:
                expires_at = start + timedelta(seconds=bucket.window_seconds + 86400)

                statement = (
                    insert(RateLimitCounter)
                    .values(
                        scope=bucket.scope,
                        key_hash=key_hash,
                        window_start=start,
                        count=1,
                        expires_at=expires_at,
                    )
                    .on_conflict_do_update(
                        index_elements=[
                            RateLimitCounter.scope,
                            RateLimitCounter.key_hash,
                            RateLimitCounter.window_start,
                        ],
                        set_={
                            "count": RateLimitCounter.count + 1,
                            "updated_at": func.now(),
                        },
                    )
                    .returning(RateLimitCounter.count)
                )

                count = session.execute(statement).scalar_one()

                if count > bucket.limit:
                    window_end = start + timedelta(seconds=bucket.window_seconds)
                    remaining = max(
                        1,
                        ceil((window_end - current_time).total_seconds()),
                    )
                    retry_after_seconds = max(
                        retry_after_seconds,
                        remaining,
                    )

    if retry_after_seconds:
        return RateLimitResult(
            allowed=False,
            retry_after_seconds=retry_after_seconds,
        )

    return RateLimitResult(allowed=True)
