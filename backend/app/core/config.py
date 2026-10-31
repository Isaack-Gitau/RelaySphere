from functools import lru_cache
from pathlib import Path

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
