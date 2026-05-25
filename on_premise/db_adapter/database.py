"""
Async SQLAlchemy database engine and session factory.

Required environment variables:
    RESOURCE_DB_HOST     — PostgreSQL host
    RESOURCE_DB_PORT     — PostgreSQL port (default 5432)
    RESOURCE_USER        — DB username
    RESOURCE_PASSWORD    — DB password
    RESOURCE_DATABASE    — DB name
"""

import os
from functools import lru_cache
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import QueuePool

from on_premise.utils.messages import VARIABLE_NOT_SET


@lru_cache()
def _get_env(name: str) -> str:
    value = os.getenv(name)
    if value is None:
        raise ValueError(f"{VARIABLE_NOT_SET}: {name}")
    return value


@lru_cache()
def get_database_url() -> str:
    host     = _get_env("RESOURCE_DB_HOST")
    port     = _get_env("RESOURCE_DB_PORT")
    user     = _get_env("RESOURCE_USER")
    password = _get_env("RESOURCE_PASSWORD")
    db_name  = _get_env("RESOURCE_DATABASE")
    return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{db_name}"


engine = create_async_engine(
    get_database_url(),
    poolclass=QueuePool,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
    pool_timeout=30,
    echo=False,
)

_async_session = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields an async DB session."""
    async with _async_session() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

