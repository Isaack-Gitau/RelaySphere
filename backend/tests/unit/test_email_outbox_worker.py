import argparse
from contextlib import contextmanager
from uuid import uuid4

import pytest

from app.integrations.smtp_transport import EmailDeliveryError
from app.models.email_outbox import EmailOutbox
from app.workers import email_outbox_worker as worker


def make_claimed_job() -> EmailOutbox:
    return EmailOutbox(
        id=uuid4(),
        event_type="email.verification",
        encrypted_payload=b"encrypted-test-payload",
        status="processing",
        attempt_count=1,
        lock_token=uuid4(),
    )


def make_session_factory(sessions, events):
    @contextmanager
    def session_context(session):
        events.append("session_open")
        try:
            yield session
        finally:
            events.append("session_close")

    contexts = iter(sessions)

    def factory():
        return session_context(next(contexts))

    return factory


def test_process_one_job_commits_claim_before_delivery(monkeypatch):
    job = make_claimed_job()
    events = []

    class FakeSession:
        def commit(self):
            events.append("commit")

    sessions = [FakeSession(), FakeSession()]

    def claim(session, **kwargs):
        events.append("claim")
        assert kwargs == {
            "batch_size": 1,
            "lease_seconds": worker.CLAIM_LEASE_SECONDS,
            "max_attempts": worker.MAX_ATTEMPTS,
        }
        return [job]

    def deliver(delivery_job):
        events.append("deliver")
        assert delivery_job.id == job.id
        assert delivery_job.event_type == job.event_type
        assert delivery_job.encrypted_payload == job.encrypted_payload
        assert events.index("commit") < events.index("deliver")

    def mark_delivered(session, job_id, lock_token):
        events.append("mark_delivered")
        assert job_id == job.id
        assert lock_token == job.lock_token
        return True

    monkeypatch.setattr(worker, "claim_email_jobs", claim)
    monkeypatch.setattr(worker, "mark_email_job_delivered", mark_delivered)

    factory = make_session_factory(sessions, events)

    assert worker.process_one_email_job(factory, deliverer=deliver) is True
    assert events.index("deliver") < events.index("mark_delivered")
    assert events.count("commit") == 2


def test_process_one_job_returns_false_when_queue_is_empty(monkeypatch):
    events = []

    class FakeSession:
        def commit(self):
            events.append("commit")

    session = FakeSession()

    monkeypatch.setattr(
        worker,
        "claim_email_jobs",
        lambda session, **kwargs: [],
    )

    factory = make_session_factory([session], events)

    assert worker.process_one_email_job(factory) is False
    assert events == ["session_open", "commit", "session_close"]


@pytest.mark.parametrize(
    ("delivery_error", "expected_transient", "expected_code"),
    [
        (
            EmailDeliveryError("smtp_temporary_failure", transient=True),
            True,
            "smtp_temporary_failure",
        ),
        (
            EmailDeliveryError("email_payload_invalid", transient=False),
            False,
            "email_payload_invalid",
        ),
    ],
)
def test_process_one_job_records_delivery_errors(
    monkeypatch,
    delivery_error,
    expected_transient,
    expected_code,
):
    job = make_claimed_job()
    events = []
    recorded = {}

    class FakeSession:
        def commit(self):
            events.append("commit")

    sessions = [FakeSession(), FakeSession()]

    monkeypatch.setattr(
        worker,
        "claim_email_jobs",
        lambda session, **kwargs: [job],
    )

    def deliver(_job):
        raise delivery_error

    def mark_failed(session, job_id, lock_token, error_code, **kwargs):
        recorded.update(
            job_id=job_id,
            lock_token=lock_token,
            error_code=error_code,
            **kwargs,
        )
        return True

    monkeypatch.setattr(worker, "mark_email_job_failed", mark_failed)

    factory = make_session_factory(sessions, events)

    assert worker.process_one_email_job(factory, deliverer=deliver) is True
    assert recorded["job_id"] == job.id
    assert recorded["lock_token"] == job.lock_token
    assert recorded["error_code"] == expected_code
    assert recorded["transient"] is expected_transient
    assert recorded["max_attempts"] == worker.MAX_ATTEMPTS
    assert events.count("commit") == 2


def test_process_one_job_converts_unexpected_error_to_safe_retry(monkeypatch):
    job = make_claimed_job()
    events = []
    recorded = {}

    class FakeSession:
        def commit(self):
            events.append("commit")

    sessions = [FakeSession(), FakeSession()]

    monkeypatch.setattr(
        worker,
        "claim_email_jobs",
        lambda session, **kwargs: [job],
    )

    def deliver(_job):
        raise RuntimeError("Sensitive internal detail")

    def mark_failed(session, job_id, lock_token, error_code, **kwargs):
        recorded.update(error_code=error_code, **kwargs)
        return True

    monkeypatch.setattr(worker, "mark_email_job_failed", mark_failed)

    factory = make_session_factory(sessions, events)

    assert worker.process_one_email_job(factory, deliverer=deliver) is True
    assert recorded["error_code"] == "email_delivery_internal_error"
    assert recorded["transient"] is True


def test_process_one_job_does_not_overwrite_a_lost_claim(monkeypatch, caplog):
    job = make_claimed_job()

    class FakeSession:
        def commit(self):
            pass

    sessions = [FakeSession(), FakeSession()]

    monkeypatch.setattr(
        worker,
        "claim_email_jobs",
        lambda session, **kwargs: [job],
    )
    monkeypatch.setattr(
        worker,
        "mark_email_job_delivered",
        lambda *args, **kwargs: False,
    )

    factory = make_session_factory(sessions, [])

    with caplog.at_level("WARNING"):
        assert worker.process_one_email_job(factory, deliverer=lambda _job: None) is True

    assert "claim is no longer active" in caplog.text


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "-inf", "not-a-number"])
def test_positive_float_rejects_invalid_values(value):
    with pytest.raises(argparse.ArgumentTypeError):
        worker._positive_float(value)


def test_positive_float_accepts_finite_positive_values():
    assert worker._positive_float("0.5") == 0.5
    assert worker._positive_float("10") == 10.0


def test_process_one_job_propagates_database_finalization_failure(monkeypatch):
    job = make_claimed_job()
    events = []

    class FakeSession:
        def __init__(self, fail_commit=False):
            self.fail_commit = fail_commit

        def commit(self):
            events.append("commit")
            if self.fail_commit:
                raise RuntimeError("Database finalization failed")

    sessions = [FakeSession(), FakeSession(fail_commit=True)]

    monkeypatch.setattr(
        worker,
        "claim_email_jobs",
        lambda session, **kwargs: [job],
    )
    monkeypatch.setattr(
        worker,
        "mark_email_job_delivered",
        lambda session, job_id, lock_token: True,
    )

    factory = make_session_factory(sessions, events)

    with pytest.raises(RuntimeError, match="Database finalization failed"):
        worker.process_one_email_job(factory, deliverer=lambda _job: None)

    assert events.count("commit") == 2
    assert events.count("session_close") == 2


def test_claim_lease_outlasts_worst_case_delivery_at_default_smtp_timeout():
    from app.core.config import Settings

    default_timeout = Settings.model_fields["smtp_timeout_seconds"].default
    # A STARTTLS delivery makes about a dozen sequential blocking network
    # operations, and each one may take up to the per-operation timeout.
    worst_case_seconds = 12 * default_timeout

    assert worker.CLAIM_LEASE_SECONDS > worst_case_seconds
