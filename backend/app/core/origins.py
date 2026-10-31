import ipaddress
import re
from urllib.parse import urlsplit

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _is_loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True

    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        # Reject ambiguous shortened numeric IPv4 forms such as 127.1.
        if all(part.isdigit() for part in host.split(".")):
            return True
        return False


def _normalize_origin(value: str, *, production: bool) -> str:
    if not value or value in {"*", "null"}:
        raise ValueError("CORS origins must be explicit HTTP(S) origins.")

    if any(character.isspace() for character in value):
        raise ValueError("CORS origins must not contain whitespace.")

    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("CORS origin is malformed.") from exc

    if (
        scheme not in {"http", "https"}
        or not parsed.netloc
        or not host
        or parsed.netloc.endswith(":")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("CORS entries must contain only scheme, host, and optional port.")

    try:
        address = ipaddress.ip_address(host)
        normalized_host = address.compressed
        if address.version == 6:
            normalized_host = f"[{normalized_host}]"
    except ValueError as exc:
        if ":" in host or host.endswith("."):
            raise ValueError("CORS origin contains an invalid hostname.") from exc

        # Reject non-standard numeric IP forms that browsers may interpret
        # as IPv4 addresses, including hexadecimal and octal notation.
        numeric_like_host = all(
            character in "0123456789abcdefABCDEFxX." for character in host
        ) and ("." in host or "x" in host.lower() or host.isdigit())
        if numeric_like_host:
            raise ValueError("CORS origin contains an ambiguous numeric host.") from exc

        try:
            normalized_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as idna_error:
            raise ValueError("CORS origin contains an invalid hostname.") from idna_error

        if len(normalized_host) > 253 or not all(
            _HOST_LABEL.fullmatch(label) for label in normalized_host.split(".")
        ):
            raise ValueError("CORS origin contains an invalid hostname.") from exc

    if production and scheme != "https":
        raise ValueError("Production CORS origins must use HTTPS.")

    if production and _is_loopback(host.lower()):
        raise ValueError("Production CORS origins must not use loopback hosts.")

    if port == (443 if scheme == "https" else 80):
        port = None

    suffix = f":{port}" if port is not None else ""
    return f"{scheme}://{normalized_host}{suffix}"


def parse_allowed_origins(raw_origins: str, *, production: bool) -> list[str]:
    """Parse, validate, and normalize a comma-separated CORS origin list."""
    if not isinstance(raw_origins, str) or not raw_origins.strip():
        raise ValueError("CORS_ALLOWED_ORIGINS must contain at least one origin.")

    entries = raw_origins.split(",")
    if any(not entry.strip() for entry in entries):
        raise ValueError("CORS_ALLOWED_ORIGINS contains an empty entry.")

    normalized = [_normalize_origin(entry.strip(), production=production) for entry in entries]

    return list(dict.fromkeys(normalized))
