"""One-off diagnostic — dumps every AIProviderConfig row across every
org, straight from the database, bypassing the UI and any caching.
Run with: docker compose exec backend uv run python scripts/dump_ai_provider_configs.py
"""
import asyncio

from sqlalchemy import select

from app.db.session import get_adapter, session_scope
from app.models.ai_provider_config import AIProviderConfig


async def main() -> None:
    adapter = get_adapter()
    async with session_scope(adapter) as session:
        rows = (await session.execute(select(AIProviderConfig))).scalars().all()
        if not rows:
            print("No AIProviderConfig rows exist at all.")
            return
        for r in rows:
            print(
                f"id={r.id} org_id={r.org_id} label={r.label!r} provider={r.provider} "
                f"auth_type={r.auth_type} app_id={r.app_id!r} is_default={r.is_default} model={r.model}"
            )


if __name__ == "__main__":
    asyncio.run(main())
