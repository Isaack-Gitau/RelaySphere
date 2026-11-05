import hashlib
import hmac
import re
import secrets

_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def generate_reservation_token() -> str:
    """Generate a cryptographically secure 256-bit reservation token."""
    return secrets.token_urlsafe(32)


def hash_reservation_token(token: str) -> str:
    """Return the SHA-256 digest of a valid reservation token."""
    if not isinstance(token, str) or not _TOKEN_PATTERN.fullmatch(token):
        raise ValueError("Invalid username reservation token.")

    return hashlib.sha256(token.encode("ascii")).hexdigest()


def verify_reservation_token(token: str, expected_hash: str) -> bool:
    """Verify a reservation token against its stored SHA-256 digest."""
    if not isinstance(token, str) or not _TOKEN_PATTERN.fullmatch(token):
        return False

    if not isinstance(expected_hash, str) or not _HASH_PATTERN.fullmatch(expected_hash):
        return False

    actual_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    return hmac.compare_digest(actual_hash, expected_hash)
