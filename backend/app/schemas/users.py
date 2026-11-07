import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


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
