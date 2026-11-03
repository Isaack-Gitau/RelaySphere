import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.email_outbox import EmailOutbox
from app.security.email_outbox_encryption import decrypt_email_payload
from app.services.email_outbox import claim_email_jobs, enqueue_email


def test_enqueue_email_creates_encrypted_pending_record(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    event_type = "email.verification"
    payload = {
        "recipient": "person@example.com",
        "verification_token": "test-verification-token",
    }

    record = enqueue_email(db_session, event_type, payload)

    stored_record = db_session.scalar(select(EmailOutbox).where(EmailOutbox.id == record.id))

    assert stored_record is not None
    assert stored_record.event_type == event_type
    assert stored_record.status == "pending"
    assert stored_record.attempt_count == 0
    assert stored_record.encrypted_payload != json.dumps(payload).encode("utf-8")
    assert payload["verification_token"].encode("utf-8") not in (stored_record.encrypted_payload)
    assert (
        decrypt_email_payload(
            stored_record.event_type,
            stored_record.encrypted_payload,
        )
        == payload
    )
    assert db_session.in_transaction()


def test_enqueue_email_record_is_removed_when_caller_rolls_back(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    record = enqueue_email(
        db_session,
        "email.verification",
        {
            "recipient": "person@example.com",
            "verification_token": "rollback-test-token",
        },
    )
    record_id = record.id

    assert db_session.get(EmailOutbox, record_id) is not None

    db_session.rollback()

    assert db_session.get(EmailOutbox, record_id) is None


def _enqueue_claim_test_job(
    session: Session,
    configured_outbox_encryption: None,
) -> EmailOutbox:
    return enqueue_email(
        session,
        "email.verification",
        {
            "recipient": "person@example.com",
            "verification_token": "claim-test-token",
        },
    )


def test_claim_email_jobs_claims_due_pending_records(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    first = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    second = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    now = datetime.now(UTC) + timedelta(seconds=1)

    claimed = claim_email_jobs(db_session, now=now)

    assert {job.id for job in claimed} == {first.id, second.id}
    assert all(job.status == "processing" for job in claimed)
    assert all(job.attempt_count == 1 for job in claimed)
    assert all(job.lock_token is not None for job in claimed)
    assert len({job.lock_token for job in claimed}) == 2
    assert all(job.locked_until == now + timedelta(seconds=60) for job in claimed)
    assert db_session.in_transaction()


def test_claim_email_jobs_skips_future_pending_records(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    now = datetime.now(UTC)
    job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    job.available_at = now + timedelta(minutes=5)
    db_session.flush()

    claimed = claim_email_jobs(db_session, now=now)

    assert claimed == []
    assert job.status == "pending"
    assert job.attempt_count == 0
    assert job.lock_token is None


def test_claim_email_jobs_reclaims_only_expired_processing_leases(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    now = datetime.now(UTC)

    active_job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    active_job.status = "processing"
    active_job.locked_until = now + timedelta(seconds=30)
    active_job.lock_token = __import__("uuid").uuid4()

    expired_job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    expired_job.status = "processing"
    expired_job.locked_until = now - timedelta(seconds=1)
    expired_job.lock_token = __import__("uuid").uuid4()

    missing_lease_job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    missing_lease_job.status = "processing"
    missing_lease_job.locked_until = None
    missing_lease_job.lock_token = __import__("uuid").uuid4()

    db_session.flush()

    claimed = claim_email_jobs(db_session, now=now)

    assert {job.id for job in claimed} == {expired_job.id, missing_lease_job.id}
    assert active_job.status == "processing"
    assert active_job.attempt_count == 0
    assert expired_job.attempt_count == 1
    assert missing_lease_job.attempt_count == 1


def test_claim_email_jobs_respects_batch_size(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    jobs = [_enqueue_claim_test_job(db_session, configured_outbox_encryption) for _ in range(3)]
    now = datetime.now(UTC) + timedelta(seconds=1)

    claimed = claim_email_jobs(db_session, batch_size=2, now=now)

    assert len(claimed) == 2
    assert len({job.id for job in claimed}) == 2
    assert all(job.status == "processing" for job in claimed)
    assert sum(job.status == "pending" for job in jobs) == 1


@pytest.mark.parametrize(
    ("kwargs", "expected_message"),
    [
        ({"batch_size": 0}, "batch_size"),
        ({"batch_size": -1}, "batch_size"),
        ({"batch_size": True}, "batch_size"),
        ({"lease_seconds": 0}, "lease_seconds"),
        ({"lease_seconds": -1}, "lease_seconds"),
        ({"lease_seconds": True}, "lease_seconds"),
        ({"now": datetime(2026, 1, 1)}, "timezone-aware"),
    ],
)
def test_claim_email_jobs_rejects_invalid_arguments(
    db_session: Session,
    kwargs: dict[str, object],
    expected_message: str,
) -> None:
    with pytest.raises(ValueError, match=expected_message):
        claim_email_jobs(db_session, **kwargs)
