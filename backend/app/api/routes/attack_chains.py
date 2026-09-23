import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_scan_run_or_404
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.attack_chain import AttackChain
from app.models.organization import User
from app.schemas.attack_chain import AttackChainOut

router = APIRouter(tags=["attack-chains"])


@router.get("/scan-runs/{scan_run_id}/attack-chains", response_model=list[AttackChainOut])
async def list_attack_chains(
    scan_run_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[AttackChain]:
    await get_scan_run_or_404(session, scan_run_id, user)
    result = await session.execute(
        select(AttackChain).where(AttackChain.scan_run_id == scan_run_id)
    )
    chains = list(result.scalars().unique().all())
    for chain in chains:
        await session.refresh(chain, attribute_names=["evidence"])
    return chains
