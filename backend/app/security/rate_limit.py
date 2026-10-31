import hashlib
import hmac
from typing import Literal

from app.core.config import get_settings

IdentifierKind = Literal["ip", "email"]


def validate_rate_limit_secret(secret: str | None) -> None:
    """Reject missing or insufficient rate-limit signing secrets."""
    if not isinstance(secret, str) or len(secret) < 32 or not secret.strip():
        raise RuntimeError("RATE_LIMIT_SECRET must contain at least 32 characters.")


def _get_secret() -> bytes:
    """Return the dedicated rate-limit HMAC secret."""
    secret = get_settings().rate_limit_secret
    validate_rate_limit_secret(secret)
    return secret.encode("utf-8")


def hash_rate_limit_identifier(
    kind: IdentifierKind,
    value: str,
) -> str:
    """Hash a normalized identifier using a versioned, purpose-specific HMAC."""
    if kind not in {"ip", "email"}:
        raise ValueError("Unsupported rate-limit identifier kind.")

    if not isinstance(value, str) or not value.strip():
        raise ValueError("Rate-limit identifier must be a non-empty string.")

    if len(value) > 512:
        raise ValueError("Rate-limit identifier is too long.")

    message = f"relaysphere:rate-limit:v1:{kind}:{value.strip()}".encode()

    return hmac.new(
        _get_secret(),
        message,
        hashlib.sha256,
    ).hexdigest()
