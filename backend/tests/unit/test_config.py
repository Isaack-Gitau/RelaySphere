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
        "CSRF_SECRET",
        "RATE_LIMIT_SECRET",
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_USERNAME",
        "SMTP_PASSWORD",
        "SMTP_FROM_EMAIL",
        "SMTP_FROM_NAME",
        "SMTP_TLS_MODE",
        "SMTP_TIMEOUT_SECONDS",
        "EMAIL_VERIFICATION_URL",
        "EMAIL_OUTBOX_ACTIVE_KEY_ID",
        "EMAIL_OUTBOX_ENCRYPTION_KEYS",
        "CORS_ALLOWED_ORIGINS",
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
    assert settings.csrf_secret == ""
    assert settings.rate_limit_secret == ""
    assert settings.email_outbox_active_key_id == ""
    assert settings.email_outbox_encryption_keys == "{}"
    assert settings.smtp_host == ""
    assert settings.smtp_port == 587
    assert settings.smtp_username == ""
    assert settings.smtp_password == ""
    assert settings.smtp_from_email == ""
    assert settings.smtp_from_name == "RelaySphere"
    assert settings.smtp_tls_mode == "starttls"
    assert settings.smtp_timeout_seconds == 10.0
    assert settings.email_verification_url == "http://localhost:5173/verify-email"
    assert settings.cors_allowed_origins == "http://localhost:5173"
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
    monkeypatch.setenv("CSRF_SECRET", "test-csrf-secret-at-least-32-characters")
    monkeypatch.setenv("RATE_LIMIT_SECRET", "test-rate-limit-secret-at-least-32-characters")
    monkeypatch.setenv("EMAIL_OUTBOX_ACTIVE_KEY_ID", "key-test-01")
    monkeypatch.setenv(
        "EMAIL_OUTBOX_ENCRYPTION_KEYS",
        '{"key-test-01":"dGVzdC1iYXNlNjQtZW5jcnlwdGlvbi1rZXk="}',
    )
    monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SMTP_PORT", "465")
    monkeypatch.setenv("SMTP_USERNAME", "relay@example.test")
    monkeypatch.setenv("SMTP_PASSWORD", "test-smtp-password")
    monkeypatch.setenv("SMTP_FROM_EMAIL", "noreply@example.test")
    monkeypatch.setenv("SMTP_FROM_NAME", "RelaySphere Test")
    monkeypatch.setenv("SMTP_TLS_MODE", "ssl")
    monkeypatch.setenv("SMTP_TIMEOUT_SECONDS", "15")
    monkeypatch.setenv(
        "EMAIL_VERIFICATION_URL",
        "https://app.example.test/verify-email",
    )
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "http://localhost:5173,https://example.test")
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "20")
    monkeypatch.setenv("SESSION_IDLE_TIMEOUT_MINUTES", "45")
    monkeypatch.setenv("SESSION_ABSOLUTE_LIFETIME_DAYS", "14")

    settings = Settings()

    assert settings.app_name == "RelaySphere Test"
    assert settings.environment == "testing"
    assert settings.access_token_secret == "test-secret-not-for-real-use"
    assert settings.csrf_secret == "test-csrf-secret-at-least-32-characters"
    assert settings.rate_limit_secret == "test-rate-limit-secret-at-least-32-characters"
    assert settings.email_outbox_active_key_id == "key-test-01"
    assert (
        settings.email_outbox_encryption_keys
        == '{"key-test-01":"dGVzdC1iYXNlNjQtZW5jcnlwdGlvbi1rZXk="}'
    )
    assert settings.smtp_host == "smtp.example.test"
    assert settings.smtp_port == 465
    assert settings.smtp_username == "relay@example.test"
    assert settings.smtp_password == "test-smtp-password"
    assert settings.smtp_from_email == "noreply@example.test"
    assert settings.smtp_from_name == "RelaySphere Test"
    assert settings.smtp_tls_mode == "ssl"
    assert settings.smtp_timeout_seconds == 15
    assert settings.email_verification_url == "https://app.example.test/verify-email"
    assert settings.cors_allowed_origins == "http://localhost:5173,https://example.test"
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
