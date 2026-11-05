import base64
import re

import pytest

from app.security.username_reservations import (
    generate_reservation_token,
    hash_reservation_token,
    verify_reservation_token,
)


def test_generated_reservation_token_has_256_bits_of_randomness() -> None:
    token = generate_reservation_token()

    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", token)
    decoded = base64.urlsafe_b64decode(token + "=")
    assert len(decoded) == 32


def test_generated_reservation_tokens_are_random() -> None:
    first = generate_reservation_token()
    second = generate_reservation_token()

    assert first != second


def test_hash_reservation_token_returns_sha256_hex_digest() -> None:
    token = generate_reservation_token()

    token_hash = hash_reservation_token(token)

    assert re.fullmatch(r"[0-9a-f]{64}", token_hash)
    assert token not in token_hash


def test_hashing_same_reservation_token_is_deterministic() -> None:
    token = generate_reservation_token()

    assert hash_reservation_token(token) == hash_reservation_token(token)


def test_verify_accepts_matching_reservation_token() -> None:
    token = generate_reservation_token()
    token_hash = hash_reservation_token(token)

    assert verify_reservation_token(token, token_hash)


def test_verify_rejects_tampered_reservation_token() -> None:
    token = generate_reservation_token()
    token_hash = hash_reservation_token(token)
    replacement = "A" if token[0] != "A" else "B"
    tampered = replacement + token[1:]

    assert not verify_reservation_token(tampered, token_hash)


@pytest.mark.parametrize(
    "token",
    ["", "invalid", "a" * 42, "a" * 44, "a" * 42 + "!"],
)
def test_hash_rejects_malformed_reservation_tokens(token: str) -> None:
    with pytest.raises(ValueError, match="Invalid username reservation token"):
        hash_reservation_token(token)


@pytest.mark.parametrize(
    ("token", "token_hash"),
    [
        ("invalid", "0" * 64),
        ("a" * 43, "invalid"),
        ("a" * 43, "A" * 64),
        ("a" * 43, ""),
    ],
)
def test_verify_rejects_malformed_credentials(
    token: str,
    token_hash: str,
) -> None:
    assert not verify_reservation_token(token, token_hash)


def test_verify_rejects_a_valid_token_against_another_hash() -> None:
    first = generate_reservation_token()
    second = generate_reservation_token()

    assert not verify_reservation_token(first, hash_reservation_token(second))
