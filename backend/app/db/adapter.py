from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession


class DatabaseAdapter(ABC):
    """One adapter per backing database. Default implementation is
    PostgresAdapter (SQLAlchemy + Alembic). Swapping to MySQL/SQL
    Server/Oracle/SQLite means implementing this interface against a
    different SQLAlchemy engine URL/dialect — application code never
    depends on a specific dialect, only on this interface and on
    ORM-level (not raw-SQL) queries.
    """

    @abstractmethod
    def get_session(self) -> AsyncIterator[AsyncSession]:
        """Yield a session scoped to a single unit of work."""
        ...

    @abstractmethod
    async def create_all(self) -> None:
        """Create all tables. Used by tests/dev bootstrap; real deploys use
        Alembic migrations instead."""
        ...

    @abstractmethod
    async def dispose(self) -> None:
        ...
