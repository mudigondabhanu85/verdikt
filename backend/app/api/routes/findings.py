import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_finding_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.finding import Finding
from app.models.organization import User
from app.schemas.finding import FindingOut, FindingStatusUpdate

router = APIRouter(tags=["findings"])


@router.patch("/findings/{finding_id}", response_model=FindingOut)
async def update_finding_status(
    finding_id: uuid.UUID,
    payload: FindingStatusUpdate,
    user: User = Depends(require_permission("finding", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> Finding:
    """An analyst's own disposition of a Finding after reviewing it —
    most commonly marking a false positive
    (retest_status="false_positive_after_review") or accepting a real
    risk ("risk_accepted") rather than deleting the record outright.
    Both are "analyst-locked" statuses (see
    app.agents.retest._ANALYST_LOCKED_STATUSES) — a later rescan's diff
    won't silently flip one back to "open" just because the same
    signal reproduced again; reopening it here first is what does that.
    """
    finding = await get_finding_or_404(session, finding_id, user)
    finding.retest_status = payload.retest_status
    await write_audit_log(
        session,
        user=user,
        action="finding.update_status",
        resource_type="finding",
        resource_id=finding_id,
        metadata={"retest_status": payload.retest_status, "title": finding.title},
    )
    await session.commit()
    await session.refresh(finding)
    return finding


@router.delete("/findings/{finding_id}", status_code=204)
async def delete_finding(
    finding_id: uuid.UUID,
    user: User = Depends(require_permission("finding", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    """Deletes a Finding outright, for a confirmed false positive an
    analyst wants gone entirely rather than just marked. Prefer
    PATCH .../false_positive_after_review over this when the record
    (and its evidence) is worth keeping for audit history — this is
    irreversible and cascades to the Finding's Evidence row and any
    linked FindingTicket.
    """
    finding = await get_finding_or_404(session, finding_id, user)
    await write_audit_log(
        session,
        user=user,
        action="finding.delete",
        resource_type="finding",
        resource_id=finding_id,
        metadata={"title": finding.title, "check_id": finding.check_id},
    )
    await session.delete(finding)
    await session.commit()
