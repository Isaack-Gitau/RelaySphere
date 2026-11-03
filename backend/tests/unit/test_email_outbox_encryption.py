import base64
import json
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.security.email_outbox_encryption import (
    EmailOutboxEncryptionError,
    decrypt_email_payload,
    encrypt_email_payload,
)

ACTIVE_KEY_ID = "key-test-02"
OLD_KEY_ID = "key-test-01"
ACTIVE_KEY = bytes(range(32))
OLD_KEY = bytes(range(32, 64))


def encoded_key(key: bytes) -> str:
    return base64.b64encode(key).decode("ascii")


def configure_key_ring(
    monkeypatch: pytest.MonkeyPatch,
    keys: dict[str, bytes] | None = None,
    active_key_id: str = ACTIVE_KEY_ID,
) -> None:
    if keys is None:
        keys = {ACTIVE_KEY_ID: ACTIVE_KEY, OLD_KEY_ID: OLD_KEY}

    encoded_keys = {key_id: encoded_key(key) for key_id, key in keys.items()}

    monkeypatch.setattr(
        "app.security.email_outbox_encryption.get_settings",
        lambda: SimpleNamespace(
            email_outbox_active_key_id=active_key_id,
            email_outbox_encryption_keys=json.dumps(encoded_keys),
        ),
    )


@pytest.fixture
def configured_encryption(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_key_ring(monkeypatch)


def test_encrypt_and_decrypt_payload(configured_encryption: None) -> None:
    payload = {
        "recipient": "person@example.com",
        "verification_token": "a-secret-verification-token",
    }

    encrypted = encrypt_email_payload("email.verification", payload)

    assert isinstance(encrypted, bytes)
    assert encrypted[0] == 2
    assert decrypt_email_payload("email.verification", encrypted) == payload


def test_decryption_rejects_duplicate_json_keys(
    configured_encryption: None,
) -> None:
    event_type = "email.verification"
    key_id = ACTIVE_KEY_ID.encode("ascii")
    nonce = bytes(range(12))
    plaintext = b'{"recipient":"first","recipient":"second"}'
    associated_data = b"relaysphere:email-outbox:v2:" + event_type.encode("ascii") + b":" + key_id

    ciphertext = AESGCM(ACTIVE_KEY).encrypt(
        nonce,
        plaintext,
        associated_data,
    )

    encrypted = bytes([2, len(key_id)]) + key_id + nonce + ciphertext

    with pytest.raises(EmailOutboxEncryptionError):
        decrypt_email_payload(event_type, encrypted)


def test_encryption_uses_a_fresh_nonce(configured_encryption: None) -> None:
    payload = {"recipient": "person@example.com", "token": "same-token"}

    first = encrypt_email_payload("email.verification", payload)
    second = encrypt_email_payload("email.verification", payload)

    assert first != second
    assert first[3:15] != second[3:15]


def test_envelope_contains_active_key_id(configured_encryption: None) -> None:
    encrypted = encrypt_email_payload("email.verification", {"token": "secret"})

    key_id_length = encrypted[1]
    key_id = encrypted[2 : 2 + key_id_length].decode("ascii")

    assert key_id == ACTIVE_KEY_ID


def test_old_key_can_decrypt_after_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_key_ring(monkeypatch, {OLD_KEY_ID: OLD_KEY}, OLD_KEY_ID)
    encrypted = encrypt_email_payload(
        "email.verification",
        {"token": "created-with-old-key"},
    )

    configure_key_ring(
        monkeypatch,
        {ACTIVE_KEY_ID: ACTIVE_KEY, OLD_KEY_ID: OLD_KEY},
        ACTIVE_KEY_ID,
    )

    assert decrypt_email_payload(
        "email.verification",
        encrypted,
    ) == {"token": "created-with-old-key"}


def test_new_encryption_uses_new_active_key_after_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_key_ring(monkeypatch, {OLD_KEY_ID: OLD_KEY}, OLD_KEY_ID)
    old_payload = encrypt_email_payload("email.verification", {"token": "old"})

    configure_key_ring(
        monkeypatch,
        {ACTIVE_KEY_ID: ACTIVE_KEY, OLD_KEY_ID: OLD_KEY},
        ACTIVE_KEY_ID,
    )
    new_payload = encrypt_email_payload("email.verification", {"token": "new"})

    assert old_payload[2 : 2 + old_payload[1]].decode("ascii") == OLD_KEY_ID
    assert new_payload[2 : 2 + new_payload[1]].decode("ascii") == ACTIVE_KEY_ID


def test_payload_cannot_be_decrypted_for_another_event_type(
    configured_encryption: None,
) -> None:
    encrypted = encrypt_email_payload("email.verification", {"token": "secret"})

    with pytest.raises(EmailOutboxEncryptionError):
        decrypt_email_payload("email.password_reset", encrypted)


def test_modified_ciphertext_is_rejected(configured_encryption: None) -> None:
    encrypted = encrypt_email_payload("email.verification", {"token": "secret"})
    tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 1])

    with pytest.raises(EmailOutboxEncryptionError):
        decrypt_email_payload("email.verification", tampered)


def test_modified_key_id_is_rejected(configured_encryption: None) -> None:
    encrypted = encrypt_email_payload("email.verification", {"token": "secret"})
    tampered = bytearray(encrypted)
    tampered[2] = ord("x") if tampered[2] != ord("x") else ord("y")

    with pytest.raises(EmailOutboxEncryptionError):
        decrypt_email_payload("email.verification", bytes(tampered))


@pytest.mark.parametrize(
    "invalid_key",
    [
        "",
        "not-base64!",
        base64.b64encode(b"too-short").decode("ascii"),
        base64.b64encode(bytes(33)).decode("ascii"),
    ],
)
def test_encryption_rejects_invalid_key(
    monkeypatch: pytest.MonkeyPatch,
    invalid_key: str,
) -> None:
    monkeypatch.setattr(
        "app.security.email_outbox_encryption.get_settings",
        lambda: SimpleNamespace(
            email_outbox_active_key_id=ACTIVE_KEY_ID,
            email_outbox_encryption_keys=json.dumps({ACTIVE_KEY_ID: invalid_key}),
        ),
    )

    with pytest.raises(EmailOutboxEncryptionError):
        encrypt_email_payload("email.verification", {"token": "secret"})


def test_encryption_rejects_missing_key_ring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.security.email_outbox_encryption.get_settings",
        lambda: SimpleNamespace(
            email_outbox_active_key_id=ACTIVE_KEY_ID,
            email_outbox_encryption_keys="{}",
        ),
    )

    with pytest.raises(EmailOutboxEncryptionError):
        encrypt_email_payload("email.verification", {"token": "secret"})


def test_encryption_rejects_missing_active_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_key_ring(monkeypatch, {OLD_KEY_ID: OLD_KEY}, ACTIVE_KEY_ID)

    with pytest.raises(EmailOutboxEncryptionError):
        encrypt_email_payload("email.verification", {"token": "secret"})


def test_encryption_rejects_malformed_key_ring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.security.email_outbox_encryption.get_settings",
        lambda: SimpleNamespace(
            email_outbox_active_key_id=ACTIVE_KEY_ID,
            email_outbox_encryption_keys="not-json",
        ),
    )

    with pytest.raises(EmailOutboxEncryptionError):
        encrypt_email_payload("email.verification", {"token": "secret"})


def test_encryption_rejects_duplicate_key_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    duplicate_keys = (
        '{"key-test-02":"'
        + encoded_key(ACTIVE_KEY)
        + '","key-test-02":"'
        + encoded_key(OLD_KEY)
        + '"}'
    )

    monkeypatch.setattr(
        "app.security.email_outbox_encryption.get_settings",
        lambda: SimpleNamespace(
            email_outbox_active_key_id=ACTIVE_KEY_ID,
            email_outbox_encryption_keys=duplicate_keys,
        ),
    )

    with pytest.raises(EmailOutboxEncryptionError):
        encrypt_email_payload("email.verification", {"token": "secret"})


def test_encryption_rejects_invalid_key_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_key_ring(monkeypatch, {ACTIVE_KEY_ID: ACTIVE_KEY}, "invalid key id")

    with pytest.raises(EmailOutboxEncryptionError):
        encrypt_email_payload("email.verification", {"token": "secret"})


def test_encryption_rejects_invalid_event_type(
    configured_encryption: None,
) -> None:
    with pytest.raises(EmailOutboxEncryptionError):
        encrypt_email_payload("Email Verification", {"token": "secret"})


def test_encryption_rejects_non_object_payload(
    configured_encryption: None,
) -> None:
    with pytest.raises(EmailOutboxEncryptionError):
        encrypt_email_payload("email.verification", ["not", "an", "object"])


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_encryption_rejects_non_standard_json_numbers(
    configured_encryption: None,
    value: float,
) -> None:
    with pytest.raises(EmailOutboxEncryptionError):
        encrypt_email_payload("email.verification", {"value": value})


def test_encryption_rejects_payload_over_64_kib(
    configured_encryption: None,
) -> None:
    payload = {"data": "x" * (64 * 1024)}

    with pytest.raises(EmailOutboxEncryptionError):
        encrypt_email_payload("email.verification", payload)


def test_decryption_rejects_envelope_over_maximum_size(
    configured_encryption: None,
) -> None:
    oversized = b"\\x02\\x01" + b"a" + bytes(12) + bytes(64 * 1024 + 17)

    with pytest.raises(EmailOutboxEncryptionError):
        decrypt_email_payload("email.verification", oversized)


def test_decryption_rejects_truncated_payload(
    configured_encryption: None,
) -> None:
    with pytest.raises(EmailOutboxEncryptionError):
        decrypt_email_payload("email.verification", b"\x02short")


def test_decryption_rejects_unknown_version(
    configured_encryption: None,
) -> None:
    encrypted = encrypt_email_payload("email.verification", {"token": "secret"})
    unsupported = bytes([99]) + encrypted[1:]

    with pytest.raises(EmailOutboxEncryptionError):
        decrypt_email_payload("email.verification", unsupported)


def test_decryption_rejects_invalid_key_id_length(
    configured_encryption: None,
) -> None:
    encrypted = encrypt_email_payload("email.verification", {"token": "secret"})
    malformed = encrypted[:1] + b"\x00" + encrypted[2:]

    with pytest.raises(EmailOutboxEncryptionError):
        decrypt_email_payload("email.verification", malformed)


def test_decryption_rejects_removed_historical_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_key_ring(monkeypatch, {OLD_KEY_ID: OLD_KEY}, OLD_KEY_ID)
    encrypted = encrypt_email_payload("email.verification", {"token": "secret"})

    configure_key_ring(monkeypatch, {ACTIVE_KEY_ID: ACTIVE_KEY}, ACTIVE_KEY_ID)

    with pytest.raises(EmailOutboxEncryptionError):
        decrypt_email_payload("email.verification", encrypted)
