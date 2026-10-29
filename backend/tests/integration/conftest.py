from collections.abc import Generator

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.core.config import get_settings


@pytest.fixture(scope="session")
def integration_test_engine() -> Generator[Engine]:
    """Connect to the dedicated integration-test database only."""
    configured_url = make_url(get_settings().database_url)

    if configured_url.database != "relaysphere":
        raise RuntimeError(
            "Integration tests stopped: DATABASE_URL must point to "
            "'relaysphere' before deriving the test database URL."
        )

    test_url = configured_url.set(database="relaysphere_test")
    engine = create_engine(test_url, pool_pre_ping=True)

    try:
        with engine.connect() as connection:
            database_name = connection.scalar(text("SELECT current_database()"))
            if database_name != "relaysphere_test":
                raise RuntimeError(
                    "Integration tests stopped: connected to an unexpected database."
                )

            users_table = connection.scalar(text("SELECT to_regclass('public.users')"))
            if users_table is None:
                raise RuntimeError(
                    "The test database is missing the users table. "
                    "Apply the existing Alembic migrations manually first."
                )

        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def db_session(
    integration_test_engine: Engine,
) -> Generator[Session]:
    """Provide a session whose changes are rolled back after each test."""
    connection = integration_test_engine.connect()
    transaction = connection.begin()
    session = Session(
        bind=connection,
        autoflush=False,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )

    try:
        yield session
    finally:
        session.close()
        if transaction.is_active:
            transaction.rollback()
        connection.close()
