from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.main import app

client = TestClient(app)


def test_health_check_returns_ok() -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_check_returns_ready_when_database_is_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = MagicMock()
    monkeypatch.setattr("app.main.get_engine", lambda: engine)

    response = client.get("/api/v1/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "database": "available",
    }
    engine.connect.return_value.__enter__.return_value.execute.assert_called_once()


def test_readiness_check_returns_503_when_database_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    connection.execute.side_effect = SQLAlchemyError("simulated database failure")
    monkeypatch.setattr("app.main.get_engine", lambda: engine)

    response = client.get("/api/v1/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "database": "unavailable",
    }
    assert "simulated database failure" not in response.text


def test_readiness_check_returns_503_when_database_is_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_configuration_error() -> None:
        raise RuntimeError("Database configuration unavailable")

    monkeypatch.setattr(
        "app.main.get_engine",
        raise_configuration_error,
    )

    response = client.get("/api/v1/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "database": "unavailable",
    }
    assert "Database configuration unavailable" not in response.text
