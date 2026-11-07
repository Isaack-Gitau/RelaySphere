import uuid

import pytest
from pydantic import BaseModel, ValidationError

from app.schemas.auth import UsernameReservationRequest
from app.schemas.users import ChangeUsernameRequest

_VALID_USERNAMES = [
    "abc",
    "a1b",
    "a_b",
    "user_123",
    "mira_njoroge",
    "a" + "b" * 28 + "c",
]
_INVALID_USERNAMES = [
    "",
    "ab",
    "a" * 31,
    "Alice",
    "ALICE",
    "1abc",
    "_abc",
    "abc_",
    "ab__cd",
    "ab-cd",
    "ab cd",
    " abc",
    "abc ",
    "caf\u00e9",
]


def _accepts(model: type[BaseModel], payload: dict[str, object]) -> bool:
    try:
        model.model_validate(payload)
    except ValidationError:
        return False
    return True


def _reservation_payload(username: str) -> dict[str, object]:
    return {"username": username, "registration_attempt_id": str(uuid.uuid4())}


@pytest.mark.parametrize(
    ("username", "expected"),
    [(name, True) for name in _VALID_USERNAMES] + [(name, False) for name in _INVALID_USERNAMES],
)
def test_username_rules_match_the_reservation_schema(username: str, expected: bool) -> None:
    assert _accepts(ChangeUsernameRequest, {"username": username}) is expected
    assert _accepts(UsernameReservationRequest, _reservation_payload(username)) is expected


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("email", "other@example.com"),
        ("display_name", "Other Name"),
        ("registration_attempt_id", "6f1c1c1e-2f6a-4b1f-9a3e-1d2c3b4a5f60"),
        ("is_active", False),
    ],
)
def test_change_request_rejects_extra_fields(field: str, value: object) -> None:
    assert not _accepts(ChangeUsernameRequest, {"username": "mira_njoroge", field: value})


def test_change_request_requires_a_username() -> None:
    assert not _accepts(ChangeUsernameRequest, {})


@pytest.mark.parametrize("value", [None, 123, True, ["mira_njoroge"]])
def test_change_request_rejects_non_string_usernames(value: object) -> None:
    assert not _accepts(ChangeUsernameRequest, {"username": value})
