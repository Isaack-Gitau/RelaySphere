import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.email_outbox import EmailOutbox
from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User
from app.models.username_claim import UsernameClaim
from app.schemas.auth import RegisterRequest
from app.security.email_outbox_encryption import decrypt_email_payload
from app.security.passwords import verify_password
from app.security.username_reservations import generate_reservation_token
from app.services import registration as registration_service
from app.services.registration import (
    EmailAlreadyRegisteredError,
    register_user,
    register_user_with_verification_token,
)
from app.services.username_reservations import (
    UsernameReservationExpiredError,
    UsernameReservationInvalidError,
    create_username_reservation,
)


def make_registration(
    session: Session,
    *,
    email: str,
    display_name: str = "Test User",
    password: str = "a-strong-test-password",
    **overrides: object,
) -> RegisterRequest:
    """Create a real reservation and return a registration request that uses it."""
    attempt_id = uuid.uuid4()
    username = f"u{uuid.uuid4().hex[:12]}"
    created = create_username_reservation(session, username, attempt_id)
    fields: dict[str, object] = {
        "email": email,
        "display_name": display_name,
        "password": password,
        "username": created.username,
        "reservation_id": created.reservation_id,
        "registration_attempt_id": attempt_id,
        "reservation_token": created.reservation_token,
    }
    fields.update(overrides)
    return RegisterRequest(**fields)


def get_claim(session: Session, username: str) -> UsernameClaim | None:
    return session.scalar(select(UsernameClaim).where(UsernameClaim.username == username))


def count_users(session: Session, email: str) -> int:
    return session.scalar(select(func.count()).select_from(User).where(User.email == email)) or 0


def test_register_user_creates_unverified_account(
    db_session: Session,
) -> None:
    registration = make_registration(
        db_session,
        email="newuser@example.com",
        display_name="New User",
    )

    user = register_user(db_session, registration)

    assert isinstance(user.id, uuid.UUID)
    assert user.email == "newuser@example.com"
    assert user.display_name == "New User"
    assert user.is_active is True
    assert user.email_verified_at is None
    assert user.password_hash is not None
    assert user.password_hash != registration.password
    assert verify_password(registration.password, user.password_hash)

    stored_user = db_session.scalar(select(User).where(User.email == "newuser@example.com"))
    assert stored_user is not None
    assert stored_user.id == user.id


def test_register_user_converts_reservation_to_permanent_claim(
    db_session: Session,
) -> None:
    registration = make_registration(db_session, email="permanent@example.com")

    user = register_user(db_session, registration)

    claim = get_claim(db_session, registration.username)
    assert claim is not None
    assert claim.id == registration.reservation_id
    assert claim.claim_type == "permanent"
    assert claim.user_id == user.id
    assert claim.registration_attempt_id is None
    assert claim.token_hash is None
    assert claim.expires_at is None
    assert user.username == registration.username


def test_register_user_rejects_duplicate_email(
    db_session: Session,
) -> None:
    registration = make_registration(
        db_session,
        email="duplicate@example.com",
        display_name="First User",
    )
    original_user = register_user(db_session, registration)

    duplicate_registration = make_registration(
        db_session,
        email="duplicate@example.com",
        display_name="Second User",
        password="another-strong-password",
    )

    with pytest.raises(EmailAlreadyRegisteredError):
        register_user(db_session, duplicate_registration)

    users = db_session.scalars(select(User).where(User.email == "duplicate@example.com")).all()

    assert len(users) == 1
    assert users[0].id == original_user.id
    assert users[0].display_name == "First User"


def test_duplicate_email_burns_a_valid_reservation_into_a_reserved_claim(
    db_session: Session,
) -> None:
    register_user(db_session, make_registration(db_session, email="keep@example.com"))
    second = make_registration(db_session, email="keep@example.com")

    with pytest.raises(EmailAlreadyRegisteredError):
        register_user(db_session, second)

    claim = get_claim(db_session, second.username)
    assert claim is not None
    assert claim.claim_type == "reserved"
    assert claim.user_id is None
    assert claim.registration_attempt_id is None
    assert claim.token_hash is None
    assert claim.expires_at is None


def test_register_user_normalizes_email(
    db_session: Session,
) -> None:
    registration = make_registration(db_session, email="  MixedCase@example.com  ")

    user = register_user(db_session, registration)

    assert user.email == "mixedcase@example.com"


BAD_RESERVATION_OVERRIDES = {
    "wrong_token": lambda: {"reservation_token": generate_reservation_token()},
    "wrong_attempt_id": lambda: {"registration_attempt_id": uuid.uuid4()},
    "wrong_username": lambda: {"username": "different_name"},
    "unknown_reservation_id": lambda: {"reservation_id": uuid.uuid4()},
}


@pytest.mark.parametrize("case", list(BAD_RESERVATION_OVERRIDES))
def test_invalid_reservation_creates_no_user_and_keeps_reservation(
    db_session: Session,
    case: str,
) -> None:
    email = f"{case}@example.com"
    valid = make_registration(db_session, email=email)
    bad = valid.model_copy(update=BAD_RESERVATION_OVERRIDES[case]())

    with pytest.raises(UsernameReservationInvalidError):
        register_user(db_session, bad)

    assert count_users(db_session, email) == 0
    claim = get_claim(db_session, valid.username)
    assert claim is not None
    assert claim.claim_type == "reservation"
    assert claim.user_id is None


def test_expired_reservation_is_rejected_and_creates_no_user(
    db_session: Session,
) -> None:
    registration = make_registration(db_session, email="expired@example.com")
    claim = get_claim(db_session, registration.username)
    assert claim is not None
    claim.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.flush()

    with pytest.raises(UsernameReservationExpiredError):
        register_user(db_session, registration)

    assert count_users(db_session, "expired@example.com") == 0
    assert claim.claim_type == "reservation"


def test_expired_reservation_with_wrong_token_does_not_reveal_expiry(
    db_session: Session,
) -> None:
    registration = make_registration(db_session, email="hiddenexpiry@example.com")
    claim = get_claim(db_session, registration.username)
    assert claim is not None
    claim.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.flush()
    wrong = registration.model_copy(update={"reservation_token": generate_reservation_token()})

    with pytest.raises(UsernameReservationInvalidError):
        register_user(db_session, wrong)


def test_consumed_reservation_cannot_be_reused(
    db_session: Session,
) -> None:
    registration = make_registration(db_session, email="first@example.com")
    register_user(db_session, registration)
    reuse = registration.model_copy(update={"email": "second@example.com"})

    with pytest.raises(UsernameReservationInvalidError):
        register_user(db_session, reuse)

    assert count_users(db_session, "second@example.com") == 0


def test_bad_reservation_behaves_the_same_for_an_existing_email(
    db_session: Session,
) -> None:
    register_user(db_session, make_registration(db_session, email="existing@example.com"))
    second = make_registration(
        db_session,
        email="existing@example.com",
        reservation_token=generate_reservation_token(),
    )

    with pytest.raises(UsernameReservationInvalidError):
        register_user(db_session, second)


def test_registration_workflow_creates_user_token_and_encrypted_email(
    db_session: Session,
    configured_outbox_encryption: None,
) -> None:
    registration = make_registration(
        db_session,
        email="verifiedflow@example.com",
        display_name="Verification Flow",
    )

    user, raw_token = register_user_with_verification_token(
        db_session,
        registration,
    )

    token_record = db_session.scalar(
        select(EmailVerificationToken).where(EmailVerificationToken.user_id == user.id)
    )
    outbox_record = db_session.scalar(
        select(EmailOutbox).where(EmailOutbox.event_type == "email.verification")
    )

    assert user.email == "verifiedflow@example.com"
    assert user.email_verified_at is None
    assert user.username == registration.username
    assert token_record is not None
    assert outbox_record is not None
    assert outbox_record.status == "pending"
    assert token_record.token_hash != raw_token

    from app.services.email_verification import hash_verification_token

    assert token_record.token_hash == hash_verification_token(raw_token)

    payload = decrypt_email_payload(
        outbox_record.event_type,
        outbox_record.encrypted_payload,
    )
    assert payload == {
        "recipient": user.email,
        "display_name": user.display_name,
        "verification_token": raw_token,
    }
    assert raw_token.encode("utf-8") not in outbox_record.encrypted_payload
    assert db_session.in_transaction()


def test_registration_workflow_leaves_rollback_to_caller_when_token_creation_fails(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = make_registration(db_session, email="tokenfailure@example.com")

    def fail_token_creation(
        session: Session,
        user_id: uuid.UUID,
    ) -> str:
        raise RuntimeError("Simulated token creation failure")

    monkeypatch.setattr(
        registration_service,
        "create_verification_token",
        fail_token_creation,
    )

    with pytest.raises(RuntimeError, match="Simulated token creation failure"):
        register_user_with_verification_token(db_session, registration)

    # The service does not own the outer transaction. In this harness the rollback
    # also discards the reservation made in the same savepoint, so the real-commit
    # test in test_registration_race.py covers "reservation survives a failure".
    db_session.rollback()

    user = db_session.scalar(select(User).where(User.email == "tokenfailure@example.com"))
    assert user is None

    tokens = db_session.scalars(
        select(EmailVerificationToken)
        .join(User, EmailVerificationToken.user_id == User.id)
        .where(User.email == "tokenfailure@example.com")
    ).all()
    assert tokens == []

    permanent = db_session.scalar(
        select(UsernameClaim).where(
            UsernameClaim.username == registration.username,
            UsernameClaim.claim_type == "permanent",
        )
    )
    assert permanent is None

    outbox_records = db_session.scalars(
        select(EmailOutbox).where(EmailOutbox.event_type == "email.verification")
    ).all()
    assert outbox_records == []


def test_registration_workflow_is_atomic_when_email_enqueue_fails(
    db_session: Session,
    configured_outbox_encryption: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = make_registration(db_session, email="enqueuefailure@example.com")

    def fail_enqueue(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Simulated email enqueue failure")

    monkeypatch.setattr(registration_service, "enqueue_email", fail_enqueue)

    with pytest.raises(RuntimeError, match="Simulated email enqueue failure"):
        register_user_with_verification_token(db_session, registration)

    db_session.rollback()

    user = db_session.scalar(select(User).where(User.email == "enqueuefailure@example.com"))
    assert user is None

    tokens = db_session.scalars(
        select(EmailVerificationToken)
        .join(User, EmailVerificationToken.user_id == User.id)
        .where(User.email == "enqueuefailure@example.com")
    ).all()
    assert tokens == []

    permanent = db_session.scalar(
        select(UsernameClaim).where(
            UsernameClaim.username == registration.username,
            UsernameClaim.claim_type == "permanent",
        )
    )
    assert permanent is None

    outbox_records = db_session.scalars(
        select(EmailOutbox).where(EmailOutbox.event_type == "email.verification")
    ).all()
    assert outbox_records == []
