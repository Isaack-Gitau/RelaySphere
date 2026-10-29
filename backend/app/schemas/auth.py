import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class RegisterRequest(BaseModel):
    """Validate a new RelaySphere account registration request."""

    email: EmailStr
    display_name: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("email", mode="after")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        """Normalize email addresses for consistent account lookup."""
        return str(value).lower()

    @field_validator("display_name", mode="before")
    @classmethod
    def normalize_display_name(cls, value: object) -> object:
        """Trim whitespace around the display name."""
        if isinstance(value, str):
            return value.strip()
        return value


class RegisterResponse(BaseModel):
    """Expose safe account fields after registration."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    display_name: str
    is_active: bool
    email_verified_at: datetime | None
    created_at: datetime


class CurrentUserResponse(BaseModel):
    """Expose safe account details for the authenticated user."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    display_name: str
    is_active: bool
    email_verified_at: datetime | None
    created_at: datetime


class VerifyEmailRequest(BaseModel):
    """Validate an email verification request."""

    token: str = Field(max_length=256)


class VerifyEmailResponse(BaseModel):
    """Return the result of a successful email verification."""

    message: str
    email_verified_at: datetime


class ResendVerificationRequest(BaseModel):
    """Validate a request to resend an email verification message."""

    email: EmailStr

    @field_validator("email", mode="after")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        """Normalize email addresses for consistent account lookup."""
        return str(value).lower()


class ResendVerificationResponse(BaseModel):
    """Return a generic response without revealing account status."""

    message: str


class LoginRequest(BaseModel):
    """Validate a login request."""

    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email", mode="after")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        """Normalize email addresses for consistent account lookup."""
        return str(value).lower()


class LoginResponse(BaseModel):
    """Return a bearer access token without exposing account secrets."""

    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int = Field(gt=0)
