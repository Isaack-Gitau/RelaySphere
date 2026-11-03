import random
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from app.models.email_outbox import EmailOutbox
from app.security.email_outbox_encryption import encrypt_email_payload

DEFAULT_MAX_DELIVERY_ATTEMPTS = 8
ATTEMPTS_EXHAUSTED_ERROR_CODE = "email_delivery_attempts_exhausted"


def enqueue_email(
    session: Session,
    event_type: str,
    payload: dict[str, Any],
) -> EmailOutbox:
    """Encrypt and enqueue an email job within the caller's transaction."""
    encrypted_payload = encrypt_email_payload(event_type, payload)

    outbox_record = EmailOutbox(
        event_type=event_type,
        encrypted_payload=encrypted_payload,
    )

    session.add(outbox_record)
    session.flush()

    return outbox_record


def claim_email_jobs(
    session: Session,
    *,
    batch_size: int = 10,
    lease_seconds: int = 60,
    max_attempts: int = DEFAULT_MAX_DELIVERY_ATTEMPTS,
    now: datetime | None = None,
) -> list[EmailOutbox]:
    """Claim due email jobs using PostgreSQL row locks.

    Expired processing jobs that have already used all of their delivery
    attempts (for example because workers crashed mid-delivery) are marked
    failed instead of being reclaimed. They never count toward the batch.

    The caller owns the transaction and must commit the claim before
    performing external delivery.
    """
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
        raise ValueError("batch_size must be a positive integer.")

    if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int):
        raise ValueError("lease_seconds must be a positive integer.")

    if lease_seconds < 1:
        raise ValueError("lease_seconds must be a positive integer.")

    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
        raise ValueError("max_attempts must be a positive integer.")

    current_time = now or datetime.now(UTC)

    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ValueError("now must be timezone-aware.")

    current_time = current_time.astimezone(UTC)
    lease_deadline = current_time + timedelta(seconds=lease_seconds)

    expired_processing = (EmailOutbox.status == "processing") & (
        EmailOutbox.locked_until.is_(None) | (EmailOutbox.locked_until <= current_time)
    )

    exhausted_jobs = session.scalars(
        select(EmailOutbox)
        .where(expired_processing, EmailOutbox.attempt_count >= max_attempts)
        .order_by(EmailOutbox.created_at, EmailOutbox.id)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
    ).all()

    for job in exhausted_jobs:
        job.status = "failed"
        job.encrypted_payload = None
        job.locked_until = None
        job.lock_token = None
        job.last_error_code = ATTEMPTS_EXHAUSTED_ERROR_CODE
        job.updated_at = current_time

    if exhausted_jobs:
        session.flush()

    eligible_job = or_(
        ((EmailOutbox.status == "pending") & (EmailOutbox.available_at <= current_time)),
        (expired_processing & (EmailOutbox.attempt_count < max_attempts)),
    )

    jobs = session.scalars(
        select(EmailOutbox)
        .where(eligible_job)
        .order_by(EmailOutbox.created_at, EmailOutbox.id)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
    ).all()

    for job in jobs:
        job.status = "processing"
        job.lock_token = uuid.uuid4()
        job.locked_until = lease_deadline
        job.attempt_count += 1

    session.flush()

    return list(jobs)


def mark_email_job_delivered(
    session: Session,
    job_id: uuid.UUID,
    lock_token: uuid.UUID,
    *,
    now: datetime | None = None,
) -> bool:
    """Mark a job delivered only while the caller owns its active claim.

    The caller owns the transaction and must commit the result.
    """
    current_time = now or datetime.now(UTC)

    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ValueError("now must be timezone-aware.")

    current_time = current_time.astimezone(UTC)

    result = session.execute(
        update(EmailOutbox)
        .where(
            EmailOutbox.id == job_id,
            EmailOutbox.status == "processing",
            EmailOutbox.lock_token == lock_token,
            EmailOutbox.locked_until > current_time,
        )
        .values(
            status="delivered",
            encrypted_payload=None,
            locked_until=None,
            lock_token=None,
            delivered_at=current_time,
            last_error_code=None,
            updated_at=current_time,
        )
        .execution_options(synchronize_session="fetch")
    )

    return result.rowcount == 1


def mark_email_job_failed(
    session: Session,
    job_id: uuid.UUID,
    lock_token: uuid.UUID,
    error_code: str,
    *,
    transient: bool,
    max_attempts: int = DEFAULT_MAX_DELIVERY_ATTEMPTS,
    base_delay_seconds: int = 30,
    max_delay_seconds: int = 21600,
    now: datetime | None = None,
) -> bool:
    """Record a delivery failure while the caller still owns an active claim.

    Transient failures are rescheduled with capped exponential backoff
    and jitter. Permanent or exhausted failures clear the encrypted payload.

    The caller owns the transaction and must commit the result.
    """
    if not re.fullmatch(r"[a-z0-9_]{1,64}", error_code):
        raise ValueError("error_code must contain 1-64 lowercase letters, digits, or underscores.")

    if not isinstance(transient, bool):
        raise ValueError("transient must be a boolean.")

    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
        raise ValueError("max_attempts must be a positive integer.")

    if (
        isinstance(base_delay_seconds, bool)
        or not isinstance(base_delay_seconds, int)
        or base_delay_seconds < 1
    ):
        raise ValueError("base_delay_seconds must be a positive integer.")

    if (
        isinstance(max_delay_seconds, bool)
        or not isinstance(max_delay_seconds, int)
        or max_delay_seconds < base_delay_seconds
    ):
        raise ValueError(
            "max_delay_seconds must be an integer at least as large as base_delay_seconds."
        )

    current_time = now or datetime.now(UTC)

    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ValueError("now must be timezone-aware.")

    current_time = current_time.astimezone(UTC)

    job = session.scalar(
        select(EmailOutbox)
        .where(
            EmailOutbox.id == job_id,
            EmailOutbox.status == "processing",
            EmailOutbox.lock_token == lock_token,
            EmailOutbox.locked_until > current_time,
        )
        .with_for_update()
    )

    if job is None:
        return False

    should_retry = transient and job.attempt_count < max_attempts

    if should_retry:
        exponential_cap = base_delay_seconds

        for _ in range(min(max(job.attempt_count - 1, 0), max_delay_seconds.bit_length())):
            exponential_cap = min(exponential_cap * 2, max_delay_seconds)

            if exponential_cap == max_delay_seconds:
                break
        retry_delay = random.uniform(0, exponential_cap)

        job.status = "pending"
        job.available_at = current_time + timedelta(seconds=retry_delay)
    else:
        job.status = "failed"
        job.encrypted_payload = None

    job.locked_until = None
    job.lock_token = None
    job.last_error_code = error_code
    job.updated_at = current_time

    session.flush()

    return True
