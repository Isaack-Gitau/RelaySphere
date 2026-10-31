import hashlib
import hmac
import re
import secrets
import uuid

from app.core.config import get_settings

_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SIGNATURE_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_VERSION = "v1"


def validate_csrf_secret(secret: str | None) -> None:
    """Reject missing or insufficient CSRF signing secrets."""
    if not isinstance(secret, str) or len(secret) < 32 or not secret.strip():
        raise RuntimeError("CSRF_SECRET must contain at least 32 characters.")


def _get_secret() -> bytes:
    """Return the dedicated CSRF signing secret, failing closed if misconfigured."""
    secret = get_settings().csrf_secret
    validate_csrf_secret(secret)
    return secret.encode("utf-8")


def _normalize_session_id(session_id: str | uuid.UUID) -> str:
    """Return a canonical UUID string for session binding."""
    try:
        return str(uuid.UUID(str(session_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("CSRF session ID must be a valid UUID.") from exc


def _signature(nonce: str, session_id: str, secret: bytes) -> str:
    """Sign a versioned, domain-separated CSRF token payload."""
    message = f"relaysphere:csrf:{_TOKEN_VERSION}:{session_id}:{nonce}".encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def generate_csrf_token(session_id: str | uuid.UUID) -> str:
    """Generate a CSRF token cryptographically bound to one server session."""
    normalized_session_id = _normalize_session_id(session_id)
    secret = _get_secret()
    nonce = secrets.token_urlsafe(32)
    signature = _signature(nonce, normalized_session_id, secret)

    return f"{_TOKEN_VERSION}.{nonce}.{signature}"


def validate_csrf_token(
    token: str | None,
    session_id: str | uuid.UUID,
) -> bool:
    """Validate token structure, signature, and its binding to a session."""
    if not isinstance(token, str) or len(token) > 160:
        return False

    try:
        normalized_session_id = _normalize_session_id(session_id)
    except ValueError:
        return False

    parts = token.split(".")
    if len(parts) != 3:
        return False

    version, nonce, supplied_signature = parts

    if version != _TOKEN_VERSION:
        return False
    if not _NONCE_PATTERN.fullmatch(nonce):
        return False
    if not _SIGNATURE_PATTERN.fullmatch(supplied_signature):
        return False

    expected_signature = _signature(
        nonce,
        normalized_session_id,
        _get_secret(),
    )

    return hmac.compare_digest(supplied_signature, expected_signature)
