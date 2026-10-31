import uuid
from types import SimpleNamespace

import pytest

from app.security import csrf


@pytest.fixture
def csrf_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        csrf,
        "get_settings",
        lambda: SimpleNamespace(csrf_secret="unit-test-csrf-secret-at-least-32-characters"),
    )


def test_generate_and_validate_csrf_token(
    csrf_settings: None,
) -> None:
    session_id = uuid.uuid4()

    token = csrf.generate_csrf_token(session_id)

    assert isinstance(token, str)
    assert csrf.validate_csrf_token(token, session_id)


def test_generated_tokens_are_random(
    csrf_settings: None,
) -> None:
    session_id = uuid.uuid4()

    first = csrf.generate_csrf_token(session_id)
    second = csrf.generate_csrf_token(session_id)

    assert first != second
    assert csrf.validate_csrf_token(first, session_id)
    assert csrf.validate_csrf_token(second, session_id)


def test_token_is_bound_to_its_session(
    csrf_settings: None,
) -> None:
    token = csrf.generate_csrf_token(uuid.uuid4())

    assert not csrf.validate_csrf_token(token, uuid.uuid4())


def test_token_rejects_tampered_signature(
    csrf_settings: None,
) -> None:
    session_id = uuid.uuid4()
    token = csrf.generate_csrf_token(session_id)
    version, nonce, signature = token.split(".")
    replacement = "0" if signature[0] != "0" else "1"
    tampered = f"{version}.{nonce}.{replacement}{signature[1:]}"

    assert not csrf.validate_csrf_token(tampered, session_id)


@pytest.mark.parametrize(
    "token",
    [
        None,
        "",
        "invalid",
        "v2.nonce.signature",
        "v1.short.signature",
        "v1." + ("a" * 43) + "." + ("z" * 64),
        "v1." + ("a" * 43) + "." + ("0" * 64) + ".extra",
    ],
)
def test_validate_rejects_missing_or_malformed_tokens(
    csrf_settings: None,
    token: str | None,
) -> None:
    assert not csrf.validate_csrf_token(token, uuid.uuid4())


def test_generate_rejects_invalid_session_id(
    csrf_settings: None,
) -> None:
    with pytest.raises(ValueError, match="valid UUID"):
        csrf.generate_csrf_token("not-a-uuid")


def test_validation_rejects_invalid_session_id(
    csrf_settings: None,
) -> None:
    assert not csrf.validate_csrf_token("v1.invalid.invalid", "not-a-uuid")


def test_generation_fails_closed_without_a_sufficient_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        csrf,
        "get_settings",
        lambda: SimpleNamespace(csrf_secret="too-short"),
    )

    with pytest.raises(RuntimeError, match="CSRF_SECRET"):
        csrf.generate_csrf_token(uuid.uuid4())


def test_validation_fails_closed_without_a_sufficient_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        csrf,
        "get_settings",
        lambda: SimpleNamespace(csrf_secret="too-short"),
    )

    with pytest.raises(RuntimeError, match="CSRF_SECRET"):
        csrf.validate_csrf_token(
            "v1." + ("a" * 43) + "." + ("0" * 64),
            uuid.uuid4(),
        )


@pytest.mark.parametrize(
    "secret",
    [None, "", "too-short", " " * 32],
)
def test_csrf_secret_validation_rejects_invalid_secrets(
    secret: str | None,
) -> None:
    with pytest.raises(RuntimeError, match="CSRF_SECRET"):
        csrf.validate_csrf_secret(secret)


def test_csrf_secret_validation_accepts_sufficient_secret() -> None:
    csrf.validate_csrf_secret("unit-test-csrf-secret-at-least-32-characters")
