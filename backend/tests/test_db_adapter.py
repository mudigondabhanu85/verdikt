from sqlalchemy import select

from app.models.organization import Organization
from tests.conftest import session_scope


async def test_create_all_and_session_roundtrip(db_adapter):
    async with session_scope(db_adapter) as session:
        session.add(Organization(name="Test Org"))
        await session.commit()

    async with session_scope(db_adapter) as session:
        result = await session.execute(select(Organization).where(Organization.name == "Test Org"))
        org = result.scalar_one()
        assert org.id is not None
        assert org.created_at is not None


async def test_dispose_is_idempotent(db_adapter):
    await db_adapter.dispose()
