from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.adapter import DatabaseAdapter
from app.db.base import Base


class PostgresAdapter(DatabaseAdapter):
    """Default DatabaseAdapter implementation. Despite the name, it is a thin
    wrapper around any SQLAlchemy async engine URL — the name reflects the
    documented production default (Postgres via Docker Compose), not a
    hardcoded dependency on the Postgres dialect. Tests point this at a
    SQLite URL instead, exercising the same code path.
    """

    def __init__(self, database_url: str, *, echo: bool = False):
        self._engine = create_async_engine(database_url, echo=echo)
        self._session_factory = async_sessionmaker(
            bind=self._engine, expire_on_commit=False
        )

    async def get_session(self) -> AsyncIterator[AsyncSession]:
        async with self._session_factory() as session:
            yield session

    async def create_all(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        await self._engine.dispose()
