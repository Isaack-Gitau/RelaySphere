import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.email_outbox import EmailOutbox
from app.security.email_outbox_encryption import encrypt_email_payload


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
    now: datetime | None = None,
) -> list[EmailOutbox]:
    """Claim due email jobs using PostgreSQL row locks.

    The caller owns the transaction and must commit the claim before
    performing external delivery.
    """
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
        raise ValueError("batch_size must be a positive integer.")

    if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int):
        raise ValueError("lease_seconds must be a positive integer.")

    if lease_seconds < 1:
        raise ValueError("lease_seconds must be a positive integer.")

    current_time = now or datetime.now(UTC)

    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ValueError("now must be timezone-aware.")

    current_time = current_time.astimezone(UTC)
    lease_deadline = current_time + timedelta(seconds=lease_seconds)

    eligible_job = or_(
        ((EmailOutbox.status == "pending") & (EmailOutbox.available_at <= current_time)),
        (
            (EmailOutbox.status == "processing")
            & (EmailOutbox.locked_until.is_(None) | (EmailOutbox.locked_until <= current_time))
        ),
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
