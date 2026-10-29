from collections.abc import Generator
from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session

from app.db import session as db_session


def test_get_engine_raises_when_database_url_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = MagicMock()
    settings.database_url = ""
    monkeypatch.setattr(db_session, "get_settings", lambda: settings)
    db_session.get_engine.cache_clear()

    try:
        with pytest.raises(RuntimeError, match="DATABASE_URL is not configured"):
            db_session.get_engine()
    finally:
        db_session.get_engine.cache_clear()


def test_get_engine_creates_and_caches_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = MagicMock()
    settings.database_url = "postgresql+psycopg://test:test@localhost/test"
    engine = MagicMock()

    monkeypatch.setattr(db_session, "get_settings", lambda: settings)
    create_engine = MagicMock(return_value=engine)
    monkeypatch.setattr(db_session, "create_engine", create_engine)
    db_session.get_engine.cache_clear()

    try:
        first_result = db_session.get_engine()
        second_result = db_session.get_engine()

        assert first_result is engine
        assert second_result is engine
        create_engine.assert_called_once_with(
            settings.database_url,
            pool_pre_ping=True,
        )
    finally:
        db_session.get_engine.cache_clear()


def test_get_session_factory_uses_expected_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = MagicMock()
    monkeypatch.setattr(db_session, "get_engine", lambda: engine)
    db_session.get_session_factory.cache_clear()

    try:
        factory = db_session.get_session_factory()

        assert factory.kw["bind"] is engine
        assert factory.kw["autoflush"] is False
        assert factory.kw["expire_on_commit"] is False

        database_session = factory()
        try:
            assert isinstance(database_session, Session)
        finally:
            database_session.close()
    finally:
        db_session.get_session_factory.cache_clear()


def test_get_db_session_closes_session_after_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_session = MagicMock(spec=Session)
    factory = MagicMock(return_value=database_session)
    monkeypatch.setattr(db_session, "get_session_factory", lambda: factory)

    generator: Generator[Session] = db_session.get_db_session()

    assert next(generator) is database_session

    with pytest.raises(StopIteration):
        next(generator)

    database_session.close.assert_called_once_with()


def test_get_db_session_closes_session_after_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_session = MagicMock(spec=Session)
    factory = MagicMock(return_value=database_session)
    monkeypatch.setattr(db_session, "get_session_factory", lambda: factory)

    generator = db_session.get_db_session()
    assert next(generator) is database_session

    with pytest.raises(ValueError, match="simulated consumer failure"):
        generator.throw(ValueError("simulated consumer failure"))

    database_session.close.assert_called_once_with()
