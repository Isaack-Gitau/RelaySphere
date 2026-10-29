from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


@lru_cache
def get_engine() -> Engine:
    """Create and cache the application's SQLAlchemy engine."""
    database_url = get_settings().database_url

    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is not configured. Set it in the local environment or .env file."
        )

    return create_engine(
        database_url,
        pool_pre_ping=True,
    )


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    """Create and cache the database session factory."""
    return sessionmaker(
        bind=get_engine(),
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )


def get_db_session() -> Generator[Session]:
    """Provide a database session and always close it afterward."""
    session = get_session_factory()()

    try:
        yield session
    finally:
        session.close()
