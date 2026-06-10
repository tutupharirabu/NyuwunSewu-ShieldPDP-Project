from collections.abc import AsyncGenerator
from functools import lru_cache
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    """Build (once) and return the async engine.

    Deferred so importing this module never instantiates a connection pool
    or requires the DB driver to be installed — only an actual request (or an
    explicit caller) triggers engine creation.
    """
    settings = get_settings()
    engine_kwargs: dict[str, Any] = {"pool_pre_ping": True, "future": True}
    if not settings.database_url.startswith("sqlite"):
        engine_kwargs.update({"pool_size": 10, "max_overflow": 20})
    return create_async_engine(settings.database_url, **engine_kwargs)


@lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Build (once) and return the session factory bound to the engine."""
    return async_sessionmaker(
        bind=get_engine(),
        expire_on_commit=False,
        autoflush=False,
        class_=AsyncSession,
    )


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with get_sessionmaker()() as session:
        yield session


def __getattr__(name: str) -> Any:
    """Lazy, backwards-compatible access for the former module-level names.

    Keeps ``from app.database.session import engine`` / ``AsyncSessionLocal``
    working while deferring construction until the name is first accessed.
    """
    if name == "engine":
        return get_engine()
    if name == "AsyncSessionLocal":
        return get_sessionmaker()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
