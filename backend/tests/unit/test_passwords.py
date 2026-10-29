from argon2 import extract_parameters

from app.security.passwords import hash_password, verify_password


def test_hash_password_returns_argon2id_hash() -> None:
    password_hash = hash_password("Correct-Horse-Battery-42!")

    assert password_hash.startswith("$argon2id$")
    assert extract_parameters(password_hash).type.name == "ID"


def test_hash_password_generates_different_hashes_for_same_password() -> None:
    password = "Correct-Horse-Battery-42!"

    first_hash = hash_password(password)
    second_hash = hash_password(password)

    assert first_hash != second_hash


def test_verify_password_accepts_correct_password() -> None:
    password = "Correct-Horse-Battery-42!"
    password_hash = hash_password(password)

    assert verify_password(password, password_hash) is True


def test_verify_password_rejects_incorrect_password() -> None:
    password_hash = hash_password("Correct-Horse-Battery-42!")

    assert verify_password("Wrong-Password-42!", password_hash) is False


def test_verify_password_rejects_malformed_hash() -> None:
    assert verify_password("any-password", "not-a-valid-hash") is False


def test_verify_password_rejects_empty_hash() -> None:
    assert verify_password("any-password", "") is False
