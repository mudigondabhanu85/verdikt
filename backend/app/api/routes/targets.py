import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.organization import User
from app.models.project import ScopeEntry
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
    await get_version_or_404(session, version_id, user)
    target = Target(version_id=version_id, **payload.model_dump())
    session.add(target)

    # Scope is enforced as a hard, independent allow-list (see
    # app.agents.scope.is_in_scope) checked on every request regardless
    # of what a Target says — a Target alone never grants anything
    # crawlable. Without this, adding a Target that has no matching
    # Scope entry (an exact host+port string match) makes every agent
    # crawl nothing while still reporting status=completed, with no
    # indication anything was misconfigured — a real, repeated failure
    # mode. Auto-deriving one matching in-scope entry here means a host
    # only ever has to be typed once.
    existing_scope = await session.execute(
        select(ScopeEntry).where(
            ScopeEntry.version_id == version_id,
            ScopeEntry.host == target.host,
            ScopeEntry.port == target.port,
        )
    )
    scope_entry = existing_scope.scalar_one_or_none()
    if scope_entry is None:
        session.add(ScopeEntry(version_id=version_id, host=target.host, port=target.port, in_scope=True))
    elif scope_entry.purpose == "login_only":
        # Explicitly adding a Target for this exact host+port is
        # stronger, more deliberate authorization than the earlier
        # login-only auto-derivation (app.api.routes.credentials) ever
        # was — the analyst is now saying this host itself is something
        # to actually test, not just something login needs to reach.
        # That should always win: leaving this entry tagged login_only
        # would keep it silently excluded from every fuzzing agent even
        # though a real Target now explicitly points at it.
        scope_entry.purpose = "target"

    await write_audit_log(
        session,
        user=user,
        action="target.create",
        resource_type="version",
        resource_id=version_id,
        metadata={"host": target.host, "port": target.port},
    )
    await session.commit()
    await session.refresh(target)
    return target


@router.get("", response_model=list[TargetOut])
async def list_targets(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("target", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[Target]:
    await get_version_or_404(session, version_id, user)
    result = await session.execute(select(Target).where(Target.version_id == version_id))
    return list(result.scalars().all())


@router.delete("/{target_id}", status_code=204)
async def delete_target(
    version_id: uuid.UUID,
    target_id: uuid.UUID,
    user: User = Depends(require_permission("target", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    await get_version_or_404(session, version_id, user)
    target = await session.get(Target, target_id)
    if target is None or target.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    await session.delete(target)
    await session.commit()
