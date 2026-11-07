import uuid
from datetime import datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    StrictBool,
    field_validator,
    model_validator,
)


class UserProfileResponse(BaseModel):
    """Expose the authenticated user's own profile."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str | None
    display_name: str
    email: EmailStr
    email_verified_at: datetime | None
    is_active: bool
    created_at: datetime


class UpdateProfileRequest(BaseModel):
    """Validate a request to change the editable fields of the caller's profile."""

    model_config = ConfigDict(extra="forbid")

    display_name: str = Field(min_length=1, max_length=80)

    @field_validator("display_name", mode="before")
    @classmethod
    def normalize_display_name(cls, value: object) -> object:
        """Trim whitespace around the display name."""
        if isinstance(value, str):
            return value.strip()
        return value


class ChangeUsernameRequest(BaseModel):
    """Validate a request to change the caller's username."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        min_length=3,
        max_length=30,
        pattern=r"^[a-z][a-z0-9_]{1,28}[a-z0-9]$",
    )

    @field_validator("username")
    @classmethod
    def reject_consecutive_underscores(cls, value: str) -> str:
        """Reject usernames containing consecutive underscores."""
        if "__" in value:
            raise ValueError("Username cannot contain consecutive underscores.")
        return value


class PreferencesResponse(BaseModel):
    """Expose the caller's complete preferences."""

    theme: Literal["system", "light", "dark"]
    show_presence: bool


class UpdatePreferencesRequest(BaseModel):
    """Validate a partial update of the caller's preferences."""

    model_config = ConfigDict(extra="forbid")

    theme: Literal["system", "light", "dark"] | None = None
    show_presence: StrictBool | None = None

    @model_validator(mode="after")
    def require_at_least_one_value(self) -> "UpdatePreferencesRequest":
        """Reject empty bodies and explicit nulls."""
        if not self.model_fields_set:
            raise ValueError("At least one preference must be provided.")
        for name in self.model_fields_set:
            if getattr(self, name) is None:
                raise ValueError(name + " must not be null.")
        return self
