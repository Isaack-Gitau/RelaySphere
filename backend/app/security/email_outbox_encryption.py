import base64
import json
import re
import secrets
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

_KEY_LENGTH = 32
_NONCE_LENGTH = 12
_TAG_LENGTH = 16
_ENVELOPE_VERSION = 2
_MAX_KEY_ID_LENGTH = 32
_MAX_PAYLOAD_LENGTH = 64 * 1024
_MAX_ENVELOPE_LENGTH = _MAX_PAYLOAD_LENGTH + 2 + _MAX_KEY_ID_LENGTH + _NONCE_LENGTH + _TAG_LENGTH

_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_EVENT_TYPE_PATTERN = re.compile(r"^[a-z0-9_.-]{1,64}$")

_ENVELOPE_FIXED_LENGTH = 1 + 1 + _NONCE_LENGTH


class EmailOutboxEncryptionError(ValueError):
    """Raised when an email outbox payload cannot be safely encrypted or decrypted."""


class EmailOutboxKeyConfigurationError(EmailOutboxEncryptionError):
    """Raised when the configured email outbox keyring is invalid or unavailable."""


class EmailOutboxKeyUnavailableError(EmailOutboxEncryptionError):
    """Raised when an envelope references a key missing from the configured keyring."""


def _validate_event_type(event_type: str) -> bytes:
    if not isinstance(event_type, str) or not _EVENT_TYPE_PATTERN.fullmatch(event_type):
        raise EmailOutboxEncryptionError("Invalid email outbox event type.")

    return event_type.encode("ascii")


def _validate_key_id(key_id: str) -> bytes:
    if not isinstance(key_id, str) or not _KEY_ID_PATTERN.fullmatch(key_id):
        raise EmailOutboxEncryptionError("Invalid email outbox encryption key ID.")

    return key_id.encode("ascii")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise EmailOutboxEncryptionError("Duplicate key in email outbox JSON object.")
        result[key] = value

    return result


def _reject_json_constant(value: str) -> None:
    raise EmailOutboxEncryptionError(f"Non-standard JSON constant is not permitted: {value}.")


def _get_key_ring() -> tuple[str, dict[str, bytes]]:
    """Load and validate the active key and all retained decryption keys."""
    settings = get_settings()
    active_key_id = settings.email_outbox_active_key_id
    encoded_key_ring = settings.email_outbox_encryption_keys

    try:
        _validate_key_id(active_key_id)

        if not isinstance(encoded_key_ring, str) or not encoded_key_ring:
            raise EmailOutboxKeyConfigurationError(
                "EMAIL_OUTBOX_ENCRYPTION_KEYS is not configured."
            )

        try:
            key_ring_data = json.loads(
                encoded_key_ring,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_json_constant,
            )
        except EmailOutboxEncryptionError as exc:
            raise EmailOutboxKeyConfigurationError(
                "EMAIL_OUTBOX_ENCRYPTION_KEYS contains invalid JSON data."
            ) from exc
        except (ValueError, TypeError) as exc:
            raise EmailOutboxKeyConfigurationError(
                "EMAIL_OUTBOX_ENCRYPTION_KEYS must be a valid JSON object."
            ) from exc

        if not isinstance(key_ring_data, dict) or not key_ring_data:
            raise EmailOutboxKeyConfigurationError(
                "EMAIL_OUTBOX_ENCRYPTION_KEYS must contain at least one key."
            )

        key_ring: dict[str, bytes] = {}

        for key_id, encoded_key in key_ring_data.items():
            try:
                _validate_key_id(key_id)
            except EmailOutboxEncryptionError as exc:
                raise EmailOutboxKeyConfigurationError(
                    "The email outbox keyring contains an invalid key ID."
                ) from exc

            if not isinstance(encoded_key, str) or not encoded_key:
                raise EmailOutboxKeyConfigurationError(
                    "Every email outbox encryption key must be a Base64 string."
                )

            try:
                key = base64.b64decode(encoded_key, validate=True)
            except (ValueError, TypeError) as exc:
                raise EmailOutboxKeyConfigurationError(
                    "An email outbox encryption key is not valid Base64."
                ) from exc

            if len(key) != _KEY_LENGTH:
                raise EmailOutboxKeyConfigurationError(
                    "Every email outbox encryption key must decode to exactly 32 bytes."
                )

            key_ring[key_id] = key

        if active_key_id not in key_ring:
            raise EmailOutboxKeyConfigurationError(
                "The active email outbox encryption key ID is not in the key ring."
            )

        return active_key_id, key_ring

    except EmailOutboxKeyConfigurationError:
        raise
    except EmailOutboxEncryptionError as exc:
        raise EmailOutboxKeyConfigurationError(
            "The email outbox encryption keyring is invalid."
        ) from exc


def _associated_data(event_type: str, key_id: str) -> bytes:
    event_type_bytes = _validate_event_type(event_type)
    key_id_bytes = _validate_key_id(key_id)

    return b"relaysphere:email-outbox:v2:" + event_type_bytes + b":" + key_id_bytes


def encrypt_email_payload(
    event_type: str,
    payload: dict[str, Any],
) -> bytes:
    """Encrypt a JSON object into a versioned AES-256-GCM envelope."""
    _validate_event_type(event_type)

    if not isinstance(payload, dict):
        raise EmailOutboxEncryptionError("Email outbox payload must be an object.")

    try:
        plaintext = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise EmailOutboxEncryptionError(
            "Email outbox payload cannot be serialized as strict JSON."
        ) from exc

    if len(plaintext) > _MAX_PAYLOAD_LENGTH:
        raise EmailOutboxEncryptionError("Email outbox payload exceeds the 64 KiB limit.")

    active_key_id, key_ring = _get_key_ring()
    key_id_bytes = _validate_key_id(active_key_id)
    nonce = secrets.token_bytes(_NONCE_LENGTH)

    ciphertext = AESGCM(key_ring[active_key_id]).encrypt(
        nonce,
        plaintext,
        _associated_data(event_type, active_key_id),
    )

    return bytes([_ENVELOPE_VERSION, len(key_id_bytes)]) + key_id_bytes + nonce + ciphertext


def decrypt_email_payload(
    event_type: str,
    encrypted_payload: bytes,
) -> dict[str, Any]:
    """Authenticate and decrypt a versioned AES-256-GCM envelope."""
    _validate_event_type(event_type)

    if not isinstance(encrypted_payload, bytes):
        raise EmailOutboxEncryptionError("Invalid encrypted email outbox payload.")

    if len(encrypted_payload) < _ENVELOPE_FIXED_LENGTH + 1 + _TAG_LENGTH:
        raise EmailOutboxEncryptionError("Encrypted email outbox payload is truncated.")

    if len(encrypted_payload) > _MAX_ENVELOPE_LENGTH:
        raise EmailOutboxEncryptionError("Encrypted email outbox payload exceeds the maximum size.")

    version = encrypted_payload[0]
    if version != _ENVELOPE_VERSION:
        raise EmailOutboxEncryptionError("Unsupported email outbox payload version.")

    key_id_length = encrypted_payload[1]
    if not 1 <= key_id_length <= _MAX_KEY_ID_LENGTH:
        raise EmailOutboxEncryptionError("Invalid email outbox encryption key ID length.")

    key_id_end = 2 + key_id_length
    nonce_end = key_id_end + _NONCE_LENGTH

    if len(encrypted_payload) < nonce_end + _TAG_LENGTH:
        raise EmailOutboxEncryptionError("Encrypted email outbox payload is truncated.")

    try:
        key_id = encrypted_payload[2:key_id_end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise EmailOutboxEncryptionError("Invalid email outbox encryption key ID.") from exc

    _validate_key_id(key_id)

    nonce = encrypted_payload[key_id_end:nonce_end]
    ciphertext = encrypted_payload[nonce_end:]

    _, key_ring = _get_key_ring()

    key = key_ring.get(key_id)
    if key is None:
        raise EmailOutboxKeyUnavailableError(
            "The encryption key required for this email outbox payload is unavailable."
        )

    try:
        plaintext = AESGCM(key).decrypt(
            nonce,
            ciphertext,
            _associated_data(event_type, key_id),
        )
        payload = json.loads(
            plaintext.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except EmailOutboxEncryptionError:
        raise
    except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EmailOutboxEncryptionError(
            "Email outbox payload authentication or decoding failed."
        ) from exc

    if not isinstance(payload, dict):
        raise EmailOutboxEncryptionError("Decrypted email outbox payload is not an object.")

    return payload
