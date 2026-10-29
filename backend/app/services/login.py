from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.user import User
from app.schemas.auth import LoginRequest
from app.security.passwords import hash_password, verify_password

_DUMMY_PASSWORD_HASH = hash_password("RelaySphere-dummy-password-not-for-login")


class InvalidCredentialsError(Exception):
    """Indicate that authentication failed without revealing why."""


def authenticate_user(session: Session, request: LoginRequest) -> User:
    """Authenticate an active, verified user and return the user."""
    email = str(request.email).strip().lower()
    user = session.scalar(select(User).where(User.email == email))

    password_hash = user.password_hash if user and user.password_hash else None
    hash_to_verify = password_hash or _DUMMY_PASSWORD_HASH

    password_is_valid = verify_password(request.password, hash_to_verify)

    if (
        user is None
        or password_hash is None
        or not password_is_valid
        or not user.is_active
        or user.email_verified_at is None
    ):
        raise InvalidCredentialsError("Invalid email or password.")

    return user


def get_access_token_expiry_seconds() -> int:
    """Return the configured access-token lifetime in seconds."""
    return get_settings().access_token_expire_minutes * 60
