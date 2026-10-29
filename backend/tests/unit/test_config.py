from pathlib import Path

import pytest

from app.core.config import Settings


@pytest.fixture
def isolated_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Prevent local environment settings from affecting config tests."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setitem(Settings.model_config, "env_file", None)

    for variable in (
        "APP_NAME",
        "APP_VERSION",
        "ENVIRONMENT",
        "API_V1_PREFIX",
        "DATABASE_URL",
        "ACCESS_TOKEN_SECRET",
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        "SESSION_IDLE_TIMEOUT_MINUTES",
        "SESSION_ABSOLUTE_LIFETIME_DAYS",
    ):
        monkeypatch.delenv(variable, raising=False)


def test_settings_use_expected_defaults(
    isolated_settings: None,
) -> None:
    settings = Settings()

    assert settings.app_name == "RelaySphere API"
    assert settings.app_version == "0.1.0"
    assert settings.environment == "development"
    assert settings.api_v1_prefix == "/api/v1"
    assert settings.database_url == ""
    assert settings.access_token_secret == ""
    assert settings.access_token_expire_minutes == 15
    assert settings.session_idle_timeout_minutes == 30
    assert settings.session_absolute_lifetime_days == 7


def test_settings_read_environment_variables(
    isolated_settings: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_NAME", "RelaySphere Test")
    monkeypatch.setenv("ENVIRONMENT", "testing")
    monkeypatch.setenv("ACCESS_TOKEN_SECRET", "test-secret-not-for-real-use")
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "20")
    monkeypatch.setenv("SESSION_IDLE_TIMEOUT_MINUTES", "45")
    monkeypatch.setenv("SESSION_ABSOLUTE_LIFETIME_DAYS", "14")

    settings = Settings()

    assert settings.app_name == "RelaySphere Test"
    assert settings.environment == "testing"
    assert settings.access_token_secret == "test-secret-not-for-real-use"
    assert settings.access_token_expire_minutes == 20
    assert settings.session_idle_timeout_minutes == 45
    assert settings.session_absolute_lifetime_days == 14


@pytest.mark.parametrize("minutes", [0, -1, 61])
def test_settings_reject_invalid_access_token_lifetime(
    isolated_settings: None,
    minutes: int,
) -> None:
    with pytest.raises(ValueError):
        Settings(access_token_expire_minutes=minutes)


@pytest.mark.parametrize("minutes", [0, -1, 1441])
def test_settings_reject_invalid_session_idle_timeout(
    isolated_settings: None,
    minutes: int,
) -> None:
    with pytest.raises(ValueError):
        Settings(session_idle_timeout_minutes=minutes)


@pytest.mark.parametrize("days", [0, -1, 31])
def test_settings_reject_invalid_session_absolute_lifetime(
    isolated_settings: None,
    days: int,
) -> None:
    with pytest.raises(ValueError):
        Settings(session_absolute_lifetime_days=days)
