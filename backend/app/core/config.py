from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[3] / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "RelaySphere API"
    app_version: str = "0.1.0"
    environment: str = "development"
    api_v1_prefix: str = "/api/v1"

    database_url: str = Field(
        default="",
        repr=False,
    )

    access_token_secret: str = Field(
        default="",
        repr=False,
    )

    csrf_secret: str = Field(
        default="",
        repr=False,
    )

    rate_limit_secret: str = Field(
        default="",
        repr=False,
    )

    email_outbox_active_key_id: str = Field(
        default="",
        repr=False,
    )

    email_outbox_encryption_keys: str = Field(
        default="{}",
        repr=False,
    )

    smtp_host: str = Field(default="", repr=False)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str = Field(default="", repr=False)
    smtp_password: str = Field(default="", repr=False)
    smtp_from_email: str = ""
    smtp_from_name: str = "RelaySphere"
    smtp_tls_mode: Literal["starttls", "ssl", "none"] = "starttls"
    smtp_timeout_seconds: float = Field(default=10.0, gt=0, le=60)

    email_verification_url: str = "http://localhost:5173/verify-email"

    cors_allowed_origins: str = "http://localhost:5173"

    access_token_expire_minutes: int = Field(
        default=15,
        gt=0,
        le=60,
    )

    session_idle_timeout_minutes: int = Field(
        default=30,
        gt=0,
        le=1440,
    )

    session_absolute_lifetime_days: int = Field(
        default=7,
        gt=0,
        le=30,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
