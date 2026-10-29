from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.user import User
from app.schemas.auth import RegisterRequest
from app.security.passwords import hash_password
from app.services.email_verification import create_verification_token


class EmailAlreadyRegisteredError(Exception):
    """Indicate that an account already uses the requested email address."""


def register_user(
    session: Session,
    registration: RegisterRequest,
) -> User:
    """Create an unverified user without committing the transaction."""
    email = str(registration.email).strip().lower()

    existing_user_id = session.scalar(select(User.id).where(User.email == email))
    if existing_user_id is not None:
        raise EmailAlreadyRegisteredError("An account with this email address already exists.")

    user = User(
        email=email,
        display_name=registration.display_name,
        password_hash=hash_password(registration.password),
        email_verified_at=None,
    )

    try:
        session.add(user)
        session.flush()
        session.refresh(user)
    except IntegrityError as exc:
        session.rollback()

        # The database's unique constraint protects concurrent registrations.
        existing_user_id = session.scalar(select(User.id).where(User.email == email))
        if existing_user_id is not None:
            raise EmailAlreadyRegisteredError(
                "An account with this email address already exists."
            ) from exc

        raise

    return user


def register_user_with_verification_token(
    session: Session,
    registration: RegisterRequest,
) -> tuple[User, str]:
    """Create a user and verification token in one transaction."""
    try:
        user = register_user(session, registration)
        raw_token = create_verification_token(session, user.id)
        session.commit()
    except Exception:
        session.rollback()
        raise

    return user, raw_token
