import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StrictBool, field_validator


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
    """Return a generic response without revealing account existence."""

    message: str


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


class ReauthRequest(BaseModel):
    """Validate a password re-entry request for the current session."""

    password: str = Field(min_length=1, max_length=128)


class ReauthResponse(BaseModel):
    """Report when the recent-reauthentication window ends."""

    reauthenticated_until: datetime


class RevokeOthersRequest(BaseModel):
    """Confirm that every other session of the account should be signed out."""

    model_config = ConfigDict(extra="forbid")

    confirm: StrictBool

    @field_validator("confirm", mode="after")
    @classmethod
    def require_true(cls, value: bool) -> bool:
        """Reject anything except an explicit true."""
        if value is not True:
            raise ValueError("confirm must be true.")
        return value


class RevokeOthersResponse(BaseModel):
    """Report how many other sessions were revoked."""

    revoked_count: int = Field(ge=0)


class SessionSummary(BaseModel):
    """Describe one active session without exposing any credentials."""

    id: uuid.UUID
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime
    reauthenticated_until: datetime | None
    is_current: bool


class SessionListResponse(BaseModel):
    """List the active sessions of the authenticated user."""

    sessions: list[SessionSummary]


class ForgotPasswordRequest(BaseModel):
    """Validate a request to start a password reset."""

    email: EmailStr

    @field_validator("email", mode="after")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        """Normalize email addresses for consistent account lookup."""
        return str(value).lower()


class ForgotPasswordResponse(BaseModel):
    """Return a generic response without revealing account status."""

    message: str


class ResetPasswordRequest(BaseModel):
    """Validate a password reset confirmation."""

    token: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=128)


class ResetPasswordResponse(BaseModel):
    """Confirm that the password was reset."""

    message: str

class EmailChangeStartRequest(BaseModel):
    """Validate a request to change the authenticated account's email."""

    model_config = ConfigDict(extra="forbid")

    new_email: EmailStr

    @field_validator("new_email", mode="after")
    @classmethod
    def normalize_new_email(cls, value: EmailStr) -> str:
        """Normalize the target address before processing."""
        return str(value).lower()


class EmailChangeStartResponse(BaseModel):
    """Return a generic response for an email-change request."""

    message: str


class EmailChangeConfirmRequest(BaseModel):
    """Validate an email-change confirmation token."""

    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, max_length=256)


class EmailChangeConfirmResponse(BaseModel):
    """Confirm that the account email was changed."""

    message: str
