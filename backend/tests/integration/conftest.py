import base64
import json
from collections.abc import Generator
from types import SimpleNamespace

import pytest
from sqlalchemy import Engine, create_engine, delete, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.rate_limit_counter import RateLimitCounter


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


@pytest.fixture(autouse=True)
def isolate_rate_limit_counters(
    integration_test_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep independent rate-limit transactions inside the test database."""
    factory = sessionmaker(
        bind=integration_test_engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )

    monkeypatch.setattr(
        "app.services.rate_limiting.get_session_factory",
        lambda: factory,
    )

    with factory.begin() as session:
        session.execute(delete(RateLimitCounter))


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


@pytest.fixture
def configured_outbox_encryption(monkeypatch: pytest.MonkeyPatch) -> None:
    key = bytes(range(32))
    encoded_key = base64.b64encode(key).decode("ascii")

    monkeypatch.setattr(
        "app.security.email_outbox_encryption.get_settings",
        lambda: SimpleNamespace(
            email_outbox_active_key_id="integration-test",
            email_outbox_encryption_keys=json.dumps({"integration-test": encoded_key}),
        ),
    )
