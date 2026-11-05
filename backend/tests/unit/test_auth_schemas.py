import uuid

import pytest
from pydantic import ValidationError

from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    UsernameReservationRequest,
    UsernameReservationResponse,
    UsernameSuggestionsRequest,
    UsernameSuggestionsResponse,
)


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


def test_username_suggestions_request_trims_display_name() -> None:
    request = UsernameSuggestionsRequest(display_name="  Isaack Gitau  ")

    assert request.display_name == "Isaack Gitau"


@pytest.mark.parametrize("display_name", ["", "   ", "\t\n"])
def test_username_suggestions_request_rejects_blank_display_name(
    display_name: str,
) -> None:
    with pytest.raises(ValidationError):
        UsernameSuggestionsRequest(display_name=display_name)


def test_username_suggestions_request_rejects_display_name_over_80_characters() -> None:
    with pytest.raises(ValidationError):
        UsernameSuggestionsRequest(display_name="a" * 81)


def test_username_suggestions_request_rejects_unexpected_fields() -> None:
    with pytest.raises(ValidationError):
        UsernameSuggestionsRequest.model_validate(
            {
                "display_name": "Isaack Gitau",
                "username": "isaack_gitau",
            }
        )


def test_username_suggestions_response_accepts_up_to_five_suggestions() -> None:
    response = UsernameSuggestionsResponse(
        suggestions=[
            "isaack_gitau",
            "isaackgitau",
            "isaack_gitau2",
            "isaack_gitau3",
            "isaack_gitau4",
        ]
    )

    assert len(response.suggestions) == 5


def test_username_suggestions_response_rejects_more_than_five_suggestions() -> None:
    with pytest.raises(ValidationError):
        UsernameSuggestionsResponse(
            suggestions=[
                "isaack_gitau",
                "isaackgitau",
                "isaack_gitau2",
                "isaack_gitau3",
                "isaack_gitau4",
                "isaack_gitau5",
            ]
        )


def test_username_reservation_request_accepts_valid_uuid_v4() -> None:
    request = UsernameReservationRequest(
        username="isaack_gitau",
        registration_attempt_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
    )

    assert request.username == "isaack_gitau"
    assert request.registration_attempt_id.version == 4


@pytest.mark.parametrize(
    "username",
    [
        "ab",
        "A_valid_name",
        "1invalid",
        "_invalid",
        "invalid_",
        "invalid__name",
        "invalid-name",
        "name with spaces",
        "a" * 31,
    ],
)
def test_username_reservation_request_rejects_invalid_usernames(
    username: str,
) -> None:
    with pytest.raises(ValidationError):
        UsernameReservationRequest(
            username=username,
            registration_attempt_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
        )


def test_username_reservation_request_rejects_non_v4_uuid() -> None:
    with pytest.raises(ValidationError):
        UsernameReservationRequest(
            username="isaack_gitau",
            registration_attempt_id=uuid.UUID("550e8400-e29b-11d4-a716-446655440000"),
        )


def test_username_reservation_request_rejects_unexpected_fields() -> None:
    with pytest.raises(ValidationError):
        UsernameReservationRequest.model_validate(
            {
                "username": "isaack_gitau",
                "registration_attempt_id": "550e8400-e29b-41d4-a716-446655440000",
                "extra": "not allowed",
            }
        )


def test_username_reservation_response_accepts_valid_credentials() -> None:
    from datetime import UTC, datetime
    from uuid import UUID

    response = UsernameReservationResponse(
        reservation_id=UUID("a1b2c3d4-e5f6-4789-8123-456789abcdef"),
        username="isaack_gitau",
        reservation_token="A" * 43,
        expires_at=datetime(2026, 11, 6, 0, 55, tzinfo=UTC),
    )

    assert response.username == "isaack_gitau"
    assert len(response.reservation_token) == 43


def test_username_reservation_response_rejects_invalid_token_shape() -> None:
    from datetime import UTC, datetime
    from uuid import UUID

    with pytest.raises(ValidationError):
        UsernameReservationResponse(
            reservation_id=UUID("a1b2c3d4-e5f6-4789-8123-456789abcdef"),
            username="isaack_gitau",
            reservation_token="not-a-valid-reservation-token",
            expires_at=datetime(2026, 11, 6, 0, 55, tzinfo=UTC),
        )
