import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from app.core.config import get_settings

_ALGORITHM = "HS256"
_MIN_SECRET_LENGTH = 32


def _get_signing_secret() -> str:
    """Return the configured signing secret or fail closed."""
    secret = get_settings().access_token_secret

    if len(secret) < _MIN_SECRET_LENGTH:
        raise RuntimeError("ACCESS_TOKEN_SECRET must contain at least 32 characters.")

    return secret


def create_access_token(subject: str, session_id: str) -> str:
    """Create a short-lived JWT bound to one server-managed session."""
    if not isinstance(subject, str) or not subject.strip():
        raise ValueError("Token subject must be a non-blank string.")
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("Token session ID must be a non-blank string.")

    try:
        session_id = str(uuid.UUID(session_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Token session ID must be a valid UUID.") from exc

    settings = get_settings()
    secret = _get_signing_secret()

    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=settings.access_token_expire_minutes)

    claims = {
        "sub": subject,
        "sid": session_id,
        "type": "access",
        "iat": now,
        "exp": expires_at,
    }

    return jwt.encode(
        claims,
        secret,
        algorithm=_ALGORITHM,
    )


def decode_access_token(token: str) -> dict[str, Any]:
    """Verify a JWT access token and return its validated claims."""
    if not token or not token.strip():
        raise ValueError("Access token must not be blank.")

    secret = _get_signing_secret()

    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=[_ALGORITHM],
            options={
                "require": ["sub", "sid", "type", "iat", "exp"],
            },
        )
    except jwt.InvalidTokenError as exc:
        raise ValueError("Invalid or expired access token.") from exc

    subject = claims.get("sub")

    if not isinstance(subject, str) or not subject.strip():
        raise ValueError("Access token has an invalid subject.")

    if claims.get("type") != "access":
        raise ValueError("Token is not an access token.")

    session_id = claims.get("sid")
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("Access token has an invalid session ID.")

    try:
        claims["sid"] = str(uuid.UUID(session_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Access token has an invalid session ID.") from exc

    return claims
