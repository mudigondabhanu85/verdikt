import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_version_or_404
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.organization import User
from app.models.target import Target
from app.schemas.target import TargetCreate, TargetOut

router = APIRouter(prefix="/versions/{version_id}/targets", tags=["targets"])


@router.post("", response_model=TargetOut, status_code=201)
async def add_target(
    version_id: uuid.UUID,
    payload: TargetCreate,
    user: User = Depends(require_permission("target", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> Target:
    await get_version_or_404(session, version_id, user.org_id)
    target = Target(version_id=version_id, **payload.model_dump())
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return target


@router.get("", response_model=list[TargetOut])
async def list_targets(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("target", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[Target]:
    await get_version_or_404(session, version_id, user.org_id)
    result = await session.execute(select(Target).where(Target.version_id == version_id))
    return list(result.scalars().all())


@router.delete("/{target_id}", status_code=204)
async def delete_target(
    version_id: uuid.UUID,
    target_id: uuid.UUID,
    user: User = Depends(require_permission("target", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    await get_version_or_404(session, version_id, user.org_id)
    target = await session.get(Target, target_id)
    if target is None or target.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    await session.delete(target)
    await session.commit()
