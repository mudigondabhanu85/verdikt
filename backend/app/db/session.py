from collections.abc import AsyncIterator
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
