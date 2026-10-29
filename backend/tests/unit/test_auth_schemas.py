import pytest
from pydantic import ValidationError

from app.schemas.auth import LoginRequest, LoginResponse, RegisterRequest


def test_registration_normalizes_email_and_display_name() -> None:
    request = RegisterRequest(
        email="  Isaack@example.com  ",
        display_name="  Isaack Gitau  ",
        password="correct-horse-battery",
    )

    assert request.email == "isaack@example.com"
    assert request.display_name == "Isaack Gitau"


@pytest.mark.parametrize(
    "email",
    ["", "not-an-email", "missing-domain@"],
)
def test_registration_rejects_invalid_email(email: str) -> None:
    with pytest.raises(ValidationError):
        RegisterRequest(
            email=email,
            display_name="Isaack",
            password="correct-horse-battery",
        )


@pytest.mark.parametrize("display_name", ["", "   ", "\t\n"])
def test_registration_rejects_blank_display_name(
    display_name: str,
) -> None:
    with pytest.raises(ValidationError):
        RegisterRequest(
            email="isaack@example.com",
            display_name=display_name,
            password="correct-horse-battery",
        )


def test_registration_rejects_display_name_over_80_characters() -> None:
    with pytest.raises(ValidationError):
        RegisterRequest(
            email="isaack@example.com",
            display_name="a" * 81,
            password="correct-horse-battery",
        )


@pytest.mark.parametrize("password", ["short", "a" * 129])
def test_registration_rejects_password_outside_length_limits(
    password: str,
) -> None:
    with pytest.raises(ValidationError):
        RegisterRequest(
            email="isaack@example.com",
            display_name="Isaack",
            password=password,
        )


def test_registration_preserves_password_exactly() -> None:
    password = "  intentional password  "

    request = RegisterRequest(
        email="isaack@example.com",
        display_name="Isaack",
        password=password,
    )

    assert request.password == password


def test_login_normalizes_email_and_preserves_password() -> None:
    password = "  intentional password  "

    request = LoginRequest(
        email="  Isaack@example.com  ",
        password=password,
    )

    assert request.email == "isaack@example.com"
    assert request.password == password


@pytest.mark.parametrize("email", ["", "not-an-email", "missing-domain@"])
def test_login_rejects_invalid_email(email: str) -> None:
    with pytest.raises(ValidationError):
        LoginRequest(email=email, password="some-password")


@pytest.mark.parametrize("password", ["", "a" * 129])
def test_login_rejects_password_outside_length_limits(
    password: str,
) -> None:
    with pytest.raises(ValidationError):
        LoginRequest(email="isaack@example.com", password=password)


def test_login_response_uses_bearer_token_type() -> None:
    response = LoginResponse(
        access_token="test-token",
        expires_in=900,
    )

    assert response.token_type == "bearer"
    assert response.expires_in == 900


def test_login_response_rejects_nonpositive_expiration() -> None:
    with pytest.raises(ValidationError):
        LoginResponse(access_token="test-token", expires_in=0)
