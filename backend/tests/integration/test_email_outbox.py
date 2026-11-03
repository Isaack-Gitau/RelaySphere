import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.email_outbox import EmailOutbox
from app.security.email_outbox_encryption import decrypt_email_payload
from app.services.email_outbox import (
    claim_email_jobs,
    enqueue_email,
    mark_email_job_delivered,
    mark_email_job_failed,
)


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


def test_mark_email_job_delivered_clears_sensitive_payload_and_lease(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    now = datetime.now(UTC) + timedelta(seconds=1)

    claimed = claim_email_jobs(db_session, now=now)
    assert len(claimed) == 1

    lock_token = claimed[0].lock_token
    assert lock_token is not None

    delivered_at = now + timedelta(seconds=5)

    result = mark_email_job_delivered(
        db_session,
        job.id,
        lock_token,
        now=delivered_at,
    )

    assert result is True
    assert job.status == "delivered"
    assert job.encrypted_payload is None
    assert job.locked_until is None
    assert job.lock_token is None
    assert job.delivered_at == delivered_at
    assert job.last_error_code is None
    assert job.updated_at == delivered_at
    assert db_session.in_transaction()


def test_mark_email_job_delivered_rejects_stale_lock_token(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    now = datetime.now(UTC) + timedelta(seconds=1)

    claimed = claim_email_jobs(db_session, now=now)
    assert len(claimed) == 1

    original_token = claimed[0].lock_token
    assert original_token is not None

    replacement_token = __import__("uuid").uuid4()
    job.lock_token = replacement_token
    db_session.flush()

    result = mark_email_job_delivered(
        db_session,
        job.id,
        original_token,
        now=now + timedelta(seconds=5),
    )

    assert result is False
    assert job.status == "processing"
    assert job.encrypted_payload is not None
    assert job.lock_token == replacement_token
    assert job.delivered_at is None


def test_mark_email_job_delivered_rejects_non_processing_job(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    original_payload = job.encrypted_payload
    supplied_token = __import__("uuid").uuid4()

    result = mark_email_job_delivered(
        db_session,
        job.id,
        supplied_token,
        now=datetime.now(UTC),
    )

    assert result is False
    assert job.status == "pending"
    assert job.encrypted_payload == original_payload
    assert job.delivered_at is None


def test_mark_email_job_delivered_rejects_expired_lease(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    now = datetime.now(UTC) + timedelta(seconds=1)

    claimed = claim_email_jobs(db_session, now=now)
    assert len(claimed) == 1

    lock_token = claimed[0].lock_token
    assert lock_token is not None

    job.locked_until = now - timedelta(seconds=1)
    db_session.flush()

    result = mark_email_job_delivered(
        db_session,
        job.id,
        lock_token,
        now=now,
    )

    assert result is False
    assert job.status == "processing"
    assert job.encrypted_payload is not None
    assert job.lock_token == lock_token
    assert job.delivered_at is None


def test_mark_email_job_failed_schedules_transient_retry(
    db_session: Session,
    configured_outbox_encryption: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import email_outbox

    job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    now = datetime.now(UTC) + timedelta(seconds=1)
    claimed = claim_email_jobs(db_session, now=now)

    assert len(claimed) == 1
    lock_token = claimed[0].lock_token
    assert lock_token is not None

    monkeypatch.setattr(email_outbox.random, "uniform", lambda lower, upper: upper)

    failed_at = now + timedelta(seconds=5)
    result = mark_email_job_failed(
        db_session,
        job.id,
        lock_token,
        "smtp_server_disconnected",
        transient=True,
        now=failed_at,
    )

    assert result is True
    assert job.status == "pending"
    assert job.attempt_count == 1
    assert job.available_at == failed_at + timedelta(seconds=30)
    assert job.encrypted_payload is not None
    assert job.lock_token is None
    assert job.locked_until is None
    assert job.last_error_code == "smtp_server_disconnected"


def test_mark_email_job_failed_permanent_error_clears_payload(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    now = datetime.now(UTC) + timedelta(seconds=1)
    claimed = claim_email_jobs(db_session, now=now)
    lock_token = claimed[0].lock_token
    assert lock_token is not None

    result = mark_email_job_failed(
        db_session,
        job.id,
        lock_token,
        "smtp_authentication_failed",
        transient=False,
        now=now + timedelta(seconds=5),
    )

    assert result is True
    assert job.status == "failed"
    assert job.encrypted_payload is None
    assert job.lock_token is None
    assert job.locked_until is None
    assert job.last_error_code == "smtp_authentication_failed"


def test_mark_email_job_failed_exhausted_attempts_clears_payload(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    job.attempt_count = 8
    now = datetime.now(UTC) + timedelta(seconds=1)
    claimed = claim_email_jobs(db_session, now=now)
    lock_token = claimed[0].lock_token
    assert lock_token is not None

    result = mark_email_job_failed(
        db_session,
        job.id,
        lock_token,
        "smtp_connection_failed",
        transient=True,
        now=now + timedelta(seconds=5),
    )

    assert result is True
    assert job.status == "failed"
    assert job.encrypted_payload is None
    assert job.last_error_code == "smtp_connection_failed"


def test_mark_email_job_failed_rejects_stale_lock_token(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    import uuid

    job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    now = datetime.now(UTC) + timedelta(seconds=1)
    claimed = claim_email_jobs(db_session, now=now)
    original_token = claimed[0].lock_token
    assert original_token is not None

    replacement_token = uuid.uuid4()
    job.lock_token = replacement_token
    db_session.flush()

    result = mark_email_job_failed(
        db_session,
        job.id,
        original_token,
        "smtp_connection_failed",
        transient=True,
        now=now + timedelta(seconds=5),
    )

    assert result is False
    assert job.status == "processing"
    assert job.encrypted_payload is not None
    assert job.lock_token == replacement_token


def test_mark_email_job_failed_rejects_expired_lease(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    now = datetime.now(UTC) + timedelta(seconds=1)
    claimed = claim_email_jobs(db_session, now=now)
    lock_token = claimed[0].lock_token
    assert lock_token is not None

    job.locked_until = now - timedelta(seconds=1)
    db_session.flush()

    result = mark_email_job_failed(
        db_session,
        job.id,
        lock_token,
        "smtp_connection_failed",
        transient=True,
        now=now,
    )

    assert result is False
    assert job.status == "processing"
    assert job.encrypted_payload is not None
    assert job.lock_token == lock_token


@pytest.mark.parametrize(
    ("kwargs", "expected_message"),
    [
        ({"error_code": "INVALID CODE"}, "error_code"),
        ({"max_attempts": 0}, "max_attempts"),
        ({"max_attempts": True}, "max_attempts"),
        ({"base_delay_seconds": 0}, "base_delay_seconds"),
        ({"max_delay_seconds": 10, "base_delay_seconds": 30}, "max_delay_seconds"),
        ({"transient": 1}, "transient"),
        ({"now": datetime(2026, 1, 1)}, "timezone-aware"),
    ],
)
def test_mark_email_job_failed_rejects_invalid_arguments(
    db_session: Session,
    kwargs: dict[str, object],
    expected_message: str,
) -> None:
    import uuid

    arguments: dict[str, object] = {
        "job_id": uuid.uuid4(),
        "lock_token": uuid.uuid4(),
        "error_code": "smtp_connection_failed",
        "transient": True,
    }
    arguments.update(kwargs)

    with pytest.raises(ValueError, match=expected_message):
        mark_email_job_failed(db_session, **arguments)


def test_mark_email_job_failed_caps_backoff_for_very_large_attempt_count(
    db_session: Session,
    configured_outbox_encryption: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import email_outbox

    job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    job.attempt_count = 1_000_000
    db_session.flush()

    now = datetime.now(UTC) + timedelta(seconds=1)
    claimed = claim_email_jobs(db_session, now=now)

    assert len(claimed) == 1
    lock_token = claimed[0].lock_token
    assert lock_token is not None

    observed_bounds: list[tuple[float, float]] = []

    def capture_upper_bound(lower: float, upper: float) -> float:
        observed_bounds.append((lower, upper))
        return upper

    monkeypatch.setattr(email_outbox.random, "uniform", capture_upper_bound)

    failed_at = now + timedelta(seconds=5)
    result = mark_email_job_failed(
        db_session,
        job.id,
        lock_token,
        "smtp_connection_failed",
        transient=True,
        max_attempts=1_000_002,
        base_delay_seconds=30,
        max_delay_seconds=21_600,
        now=failed_at,
    )

    assert result is True
    assert observed_bounds == [(0, 21_600)]
    assert job.status == "pending"
    assert job.available_at == failed_at + timedelta(seconds=21_600)
    assert job.encrypted_payload is not None


def _make_processing_job(
    session: Session,
    configured_outbox_encryption: None,
    *,
    attempt_count: int,
    locked_until: datetime | None,
) -> EmailOutbox:
    import uuid

    job = _enqueue_claim_test_job(session, configured_outbox_encryption)
    job.status = "processing"
    job.attempt_count = attempt_count
    job.locked_until = locked_until
    job.lock_token = uuid.uuid4()
    session.flush()

    return job


@pytest.mark.parametrize("lease_offset_seconds", [-1, None])
def test_claim_email_jobs_fails_expired_jobs_that_exhausted_their_attempts(
    db_session: Session,
    configured_outbox_encryption: None,
    lease_offset_seconds: int | None,
) -> None:
    now = datetime.now(UTC)
    locked_until = None
    if lease_offset_seconds is not None:
        locked_until = now + timedelta(seconds=lease_offset_seconds)

    job = _make_processing_job(
        db_session,
        configured_outbox_encryption,
        attempt_count=8,
        locked_until=locked_until,
    )

    claimed = claim_email_jobs(db_session, now=now)

    assert claimed == []
    assert job.status == "failed"
    assert job.attempt_count == 8
    assert job.encrypted_payload is None
    assert job.lock_token is None
    assert job.locked_until is None
    assert job.last_error_code == "email_delivery_attempts_exhausted"
    assert job.updated_at == now


def test_claim_email_jobs_does_not_fail_exhausted_job_with_active_lease(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    now = datetime.now(UTC)
    job = _make_processing_job(
        db_session,
        configured_outbox_encryption,
        attempt_count=8,
        locked_until=now + timedelta(seconds=30),
    )
    original_token = job.lock_token

    claimed = claim_email_jobs(db_session, now=now)

    assert claimed == []
    assert job.status == "processing"
    assert job.attempt_count == 8
    assert job.encrypted_payload is not None
    assert job.lock_token == original_token
    assert job.last_error_code is None


def test_claim_email_jobs_reclaims_expired_job_below_attempt_limit(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    now = datetime.now(UTC)
    job = _make_processing_job(
        db_session,
        configured_outbox_encryption,
        attempt_count=7,
        locked_until=now - timedelta(seconds=1),
    )

    claimed = claim_email_jobs(db_session, now=now)

    assert [claimed_job.id for claimed_job in claimed] == [job.id]
    assert job.status == "processing"
    assert job.attempt_count == 8
    assert job.encrypted_payload is not None
    assert job.locked_until == now + timedelta(seconds=60)


def test_exhausted_jobs_do_not_consume_the_claim_batch(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    now = datetime.now(UTC) + timedelta(seconds=1)

    exhausted = [
        _make_processing_job(
            db_session,
            configured_outbox_encryption,
            attempt_count=8,
            locked_until=now - timedelta(seconds=1),
        )
        for _ in range(2)
    ]
    healthy = [_enqueue_claim_test_job(db_session, configured_outbox_encryption) for _ in range(2)]

    claimed = claim_email_jobs(db_session, batch_size=2, now=now)

    assert {job.id for job in claimed} == {job.id for job in healthy}
    assert all(job.status == "processing" for job in healthy)
    assert all(job.attempt_count == 1 for job in healthy)
    assert all(job.status == "failed" for job in exhausted)
    assert all(job.encrypted_payload is None for job in exhausted)


def test_claim_email_jobs_honors_custom_max_attempts(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    now = datetime.now(UTC)
    expired = now - timedelta(seconds=1)

    at_limit = _make_processing_job(
        db_session,
        configured_outbox_encryption,
        attempt_count=2,
        locked_until=expired,
    )
    below_limit = _make_processing_job(
        db_session,
        configured_outbox_encryption,
        attempt_count=1,
        locked_until=expired,
    )

    claimed = claim_email_jobs(db_session, max_attempts=2, now=now)

    assert [job.id for job in claimed] == [below_limit.id]
    assert below_limit.attempt_count == 2
    assert at_limit.status == "failed"
    assert at_limit.last_error_code == "email_delivery_attempts_exhausted"


def test_repeated_worker_crashes_cannot_exceed_the_attempt_limit(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    job = _enqueue_claim_test_job(db_session, configured_outbox_encryption)
    start = datetime.now(UTC) + timedelta(seconds=1)

    for attempt in range(1, 9):
        now = start + timedelta(seconds=61 * attempt)
        claimed = claim_email_jobs(db_session, now=now)

        assert [claimed_job.id for claimed_job in claimed] == [job.id]
        assert job.attempt_count == attempt
        assert job.status == "processing"

    # The eighth worker crashed as well. Once its lease expires, the job
    # must be failed instead of being handed to a ninth worker.
    final_time = start + timedelta(seconds=61 * 9)
    claimed = claim_email_jobs(db_session, now=final_time)

    assert claimed == []
    assert job.status == "failed"
    assert job.attempt_count == 8
    assert job.encrypted_payload is None
    assert job.last_error_code == "email_delivery_attempts_exhausted"


@pytest.mark.parametrize("max_attempts", [0, -1, True, "8"])
def test_claim_email_jobs_rejects_invalid_max_attempts(
    db_session: Session,
    max_attempts: object,
) -> None:
    with pytest.raises(ValueError, match="max_attempts"):
        claim_email_jobs(db_session, max_attempts=max_attempts)
