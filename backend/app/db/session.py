from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.adapter import DatabaseAdapter
from app.db.postgres_adapter import PostgresAdapter


@lru_cache
def get_adapter() -> DatabaseAdapter:
    settings = get_settings()
    return PostgresAdapter(settings.database_url)


async def get_db_session() -> AsyncIterator[AsyncSession]:
    adapter = get_adapter()
    async for session in adapter.get_session():
        yield session


@asynccontextmanager
async def session_scope(adapter: DatabaseAdapter) -> AsyncIterator[AsyncSession]:
    """Opens one session from a DatabaseAdapter outside of FastAPI's
    request/Depends lifecycle — for background tasks and tests, where
    there's no request to scope a Depends()-managed session to.
    """
    gen = adapter.get_session()
    session = await gen.__anext__()
    try:
        yield session
    finally:
        await gen.aclose()
