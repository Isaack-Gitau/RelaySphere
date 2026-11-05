import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.email_change import EMAIL_CHANGE_EMAIL_EVENT
from app.db.session import get_db_session
from app.main import app
from app.models.email_change_request import EmailChangeRequest
from app.models.email_outbox import EmailOutbox
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.security import tokens
from app.security.email_outbox_encryption import decrypt_email_payload
from app.services.email_change import (
    hash_email_change_token,
    request_email_change,
)
from app.services.refresh_sessions import create_refresh_session


@pytest.fixture
def api_client(db_session: Session) -> Generator[TestClient]:
    def override_db_session() -> Generator[Session]:
        yield db_session

    app.dependency_overrides[get_db_session] = override_db_session

    try:
        with TestClient(app, headers={"Origin": "http://localhost:5173"}) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db_session, None)


@pytest.fixture(autouse=True)
def token_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tokens,
        "get_settings",
        lambda: SimpleNamespace(
            access_token_secret="integration-test-secret-at-least-32-characters",
            access_token_expire_minutes=15,
        ),
    )


def create_api_user(
    session: Session,
    *,
    reauthenticated: bool = True,
    session_count: int = 1,
) -> tuple[User, list[RefreshSession], dict[str, str]]:
    now = datetime.now(UTC)
    user = User(
        email=f"email-change-api-{uuid.uuid4().hex}@example.com",
        display_name="Email Change API Test",
        password_hash="unused-test-hash",
        is_active=True,
        email_verified_at=now,
    )
    session.add(user)
    session.flush()

    for _ in range(session_count):
        create_refresh_session(session, user.id)

    records = list(
        session.scalars(
            select(RefreshSession)
            .where(RefreshSession.user_id == user.id)
            .order_by(RefreshSession.created_at, RefreshSession.id)
        ).all()
    )
    assert len(records) == session_count

    current = records[0]
    current.last_used_at = now
    if reauthenticated:
        current.reauthenticated_at = now

    session.flush()

    access_token = tokens.create_access_token(
        subject=str(user.id),
        session_id=str(current.id),
    )

    return user, records, {"Authorization": f"Bearer {access_token}"}


def test_email_change_request_requires_authentication(
    api_client: TestClient,
) -> None:
    response = api_client.post(
        "/api/v1/auth/email-change/request",
        json={"new_email": "new-address@example.com"},
    )

    assert response.status_code == 401


def test_email_change_request_requires_recent_reauthentication(
    api_client: TestClient,
    db_session: Session,
) -> None:
    _, _, headers = create_api_user(db_session, reauthenticated=False)

    response = api_client.post(
        "/api/v1/auth/email-change/request",
        json={"new_email": "new-address@example.com"},
        headers=headers,
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "reauthentication_required"}

    assert db_session.scalar(select(EmailChangeRequest)) is None
    assert db_session.scalar(select(EmailOutbox)) is None


def test_email_change_request_creates_hashed_request_and_encrypted_outbox(
    api_client: TestClient,
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    user, _, headers = create_api_user(db_session)
    new_email = f"new-{uuid.uuid4().hex}@example.com"

    response = api_client.post(
        "/api/v1/auth/email-change/request",
        json={"new_email": new_email},
        headers=headers,
    )

    assert response.status_code == 202
    assert response.json() == {
        "message": "If the address is eligible, a confirmation email will be sent shortly."
    }

    requests = list(db_session.scalars(select(EmailChangeRequest)).all())
    outbox_jobs = list(db_session.scalars(select(EmailOutbox)).all())

    assert len(requests) == 1
    assert len(outbox_jobs) == 1

    change_request = requests[0]
    outbox_job = outbox_jobs[0]

    assert change_request.user_id == user.id
    assert change_request.new_email == new_email
    assert change_request.used_at is None
    assert change_request.superseded_at is None

    assert outbox_job.event_type == EMAIL_CHANGE_EMAIL_EVENT
    assert outbox_job.encrypted_payload is not None

    payload = decrypt_email_payload(
        outbox_job.event_type,
        outbox_job.encrypted_payload,
    )

    raw_token = payload["email_change_token"]

    assert payload == {
        "recipient": new_email,
        "display_name": user.display_name,
        "email_change_token": raw_token,
    }
    assert isinstance(raw_token, str) and raw_token
    assert change_request.token_hash == hash_email_change_token(raw_token)
    assert raw_token.encode("utf-8") not in outbox_job.encrypted_payload
    assert raw_token != change_request.token_hash
    assert user.email != new_email


@pytest.mark.parametrize("target_kind", ["current", "already_registered"])
def test_email_change_request_uses_generic_response_for_ineligible_addresses(
    api_client: TestClient,
    db_session: Session,
    target_kind: str,
) -> None:
    user, _, headers = create_api_user(db_session)

    if target_kind == "current":
        target_email = user.email
    else:
        existing_user = User(
            email=f"existing-{uuid.uuid4().hex}@example.com",
            display_name="Existing Account",
            password_hash="unused-test-hash",
            is_active=True,
            email_verified_at=datetime.now(UTC),
        )
        db_session.add(existing_user)
        db_session.flush()
        target_email = existing_user.email

    response = api_client.post(
        "/api/v1/auth/email-change/request",
        json={"new_email": target_email},
        headers=headers,
    )

    assert response.status_code == 202
    assert response.json() == {
        "message": "If the address is eligible, a confirmation email will be sent shortly."
    }

    assert db_session.scalar(select(EmailChangeRequest)) is None
    assert db_session.scalar(select(EmailOutbox)) is None


def test_email_change_confirmation_updates_email_and_revokes_all_sessions(
    api_client: TestClient,
    db_session: Session,
) -> None:
    user, records, _ = create_api_user(
        db_session,
        reauthenticated=False,
        session_count=2,
    )
    new_email = f"confirmed-{uuid.uuid4().hex}@example.com"

    result = request_email_change(db_session, user.id, new_email)
    assert result is not None

    _, normalized_email, raw_token = result
    assert normalized_email == new_email
    db_session.commit()

    response = api_client.post(
        "/api/v1/auth/email-change/confirm",
        json={"token": raw_token},
    )

    assert response.status_code == 200
    assert response.json() == {
        "message": "Email address updated successfully. Please sign in again."
    }

    db_session.refresh(user)
    assert user.email == new_email
    assert user.email_verified_at is not None

    change_request = db_session.scalar(
        select(EmailChangeRequest).where(
            EmailChangeRequest.token_hash == hash_email_change_token(raw_token)
        )
    )
    assert change_request is not None
    assert change_request.used_at is not None

    for record in records:
        db_session.refresh(record)
        assert record.revoked_at is not None


def test_email_change_confirmation_rejects_invalid_token(
    api_client: TestClient,
    db_session: Session,
) -> None:
    response = api_client.post(
        "/api/v1/auth/email-change/confirm",
        json={"token": "not-a-valid-email-change-token"},
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Invalid or expired confirmation token."
    }

    assert db_session.scalar(select(EmailChangeRequest)) is None


def test_email_change_request_is_rate_limited(
    api_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    db_session: Session,
) -> None:
    from app.services.rate_limiting import RateLimitResult

    _, _, headers = create_api_user(db_session)

    observed: dict[str, object] = {}

    def deny_request(buckets: list[object]) -> RateLimitResult:
        observed["buckets"] = buckets
        return RateLimitResult(allowed=False, retry_after_seconds=37)

    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.consume_rate_limit_buckets",
        deny_request,
    )

    response = api_client.post(
        "/api/v1/auth/email-change/request",
        json={"new_email": "rate-limited@example.com"},
        headers=headers,
    )

    assert response.status_code == 429
    assert response.json() == {
        "detail": "Too many requests. Please try again later."
    }
    assert response.headers["retry-after"] == "37"

    buckets = observed["buckets"]
    assert isinstance(buckets, list)
    assert [
        (
            bucket.scope,
            bucket.kind,
            bucket.limit,
            bucket.window_seconds,
        )
        for bucket in buckets
    ] == [
        ("auth:email-change-request:ip", "ip", 10, 900),
        ("auth:email-change-request:user", "email", 5, 900),
    ]

    assert db_session.scalar(select(EmailChangeRequest)) is None
    assert db_session.scalar(select(EmailOutbox)) is None


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        (
            "/api/v1/auth/email-change/request",
            {"new_email": "attacker-target@example.com"},
        ),
        (
            "/api/v1/auth/email-change/confirm",
            {"token": "untrusted-origin-test-token"},
        ),
    ],
)
def test_email_change_endpoints_reject_untrusted_origins_before_processing(
    api_client: TestClient,
    path: str,
    payload: dict[str, str],
) -> None:
    response = api_client.post(
        path,
        json=payload,
        headers={"Origin": "https://attacker.example"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Untrusted request origin."}
