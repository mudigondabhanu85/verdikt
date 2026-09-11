"""One-off diagnostic — dumps the 5 most recent scan runs' token/cost
tracking and status. Run with:
docker compose exec backend uv run python scripts/dump_recent_scans.py
"""
import asyncio

from sqlalchemy import select

from app.db.session import get_adapter, session_scope
from app.models.scan import ScanRun


async def main() -> None:
    adapter = get_adapter()
    async with session_scope(adapter) as session:
        rows = (
            await session.execute(select(ScanRun).order_by(ScanRun.started_at.desc()).limit(5))
        ).scalars().all()
        if not rows:
            print("No ScanRun rows exist at all.")
            return
        for r in rows:
            print(
                f"id={r.id} status={r.status} started_at={r.started_at} "
                f"cost={r.llm_cost_usd} in_tokens={r.llm_input_tokens} out_tokens={r.llm_output_tokens}"
            )


if __name__ == "__main__":
    asyncio.run(main())
