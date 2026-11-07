import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.schemas.users import UpdateProfileRequest, UserProfileResponse

_PROFILE_FIELDS = {
    "id",
    "username",
    "display_name",
    "email",
    "email_verified_at",
    "is_active",
    "created_at",
}


def test_update_request_trims_the_display_name() -> None:
    assert UpdateProfileRequest(display_name="  Isaack Gitau  ").display_name == "Isaack Gitau"


def test_update_request_accepts_an_eighty_character_name() -> None:
    assert UpdateProfileRequest(display_name="a" * 80).display_name == "a" * 80


@pytest.mark.parametrize("value", ["", "   ", "a" * 81, None, 123])
def test_update_request_rejects_invalid_display_names(value: object) -> None:
    with pytest.raises(ValidationError):
        UpdateProfileRequest.model_validate({"display_name": value})


def test_update_request_requires_a_display_name() -> None:
    with pytest.raises(ValidationError):
        UpdateProfileRequest.model_validate({})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("email", "other@example.com"),
        ("is_active", False),
        ("email_verified_at", "2026-01-01T00:00:00Z"),
        ("username", "new_name"),
        ("password", "a-strong-test-password"),
    ],
)
def test_update_request_rejects_protected_and_unknown_fields(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        UpdateProfileRequest.model_validate({"display_name": "Valid Name", field: value})


@pytest.mark.parametrize("username", [None, "isaack_gitau"])
def test_profile_response_reads_from_a_user_like_object(username: str | None) -> None:
    created_at = datetime.now(UTC)
    user = SimpleNamespace(
        id=uuid.uuid4(),
        username=username,
        display_name="Isaack",
        email="isaack@example.com",
        email_verified_at=None,
        is_active=True,
        created_at=created_at,
    )

    response = UserProfileResponse.model_validate(user)

    assert response.username == username
    assert response.display_name == "Isaack"
    assert response.created_at == created_at


def test_profile_response_exposes_only_the_documented_fields() -> None:
    assert set(UserProfileResponse.model_fields) == _PROFILE_FIELDS
