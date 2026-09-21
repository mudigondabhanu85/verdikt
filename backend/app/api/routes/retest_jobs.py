"""§8 per-finding retest — POST triggers a single, cheap re-verification
of one Finding's specific check (see app.agents.retest_registry for
what's actually covered and why). Deliberately synchronous, unlike a
full scan run's BackgroundTasks flow: every registered handler is one
HTTP request (or one real-browser page load) rather than a whole
recon-then-agents pipeline, so there's no need for the polling
machinery a multi-minute scan run needs.
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.http_client import ScopedHttpClient
from app.agents.retest_registry import RETEST_HANDLERS
from app.api.deps import get_finding_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.finding import RETEST_STATUSES
from app.models.organization import User
from app.models.project import ScopeEntry
from app.models.retest_job import RetestJob
from app.models.scan import ScanRun
from app.schemas.retest_job import RetestJobOut

router = APIRouter(tags=["retest-jobs"])

# A rescan diff (app.agents.retest) already respects these — a
# single-finding retest must never silently override a human risk
# decision either.
_ANALYST_LOCKED_STATUSES = ("risk_accepted", "false_positive_after_review")

assert set(_ANALYST_LOCKED_STATUSES) <= set(RETEST_STATUSES)


@router.post("/findings/{finding_id}/retest", response_model=RetestJobOut, status_code=201)
async def retest_finding(
    finding_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> RetestJob:
    finding = await get_finding_or_404(session, finding_id, user.org_id)
    scan_run = await session.get(ScanRun, finding.scan_run_id)
    scope_entries = list(
        (
            await session.execute(select(ScopeEntry).where(ScopeEntry.version_id == scan_run.version_id))
        ).scalars()
    )

    job = RetestJob(finding_id=finding.id, requested_by=user.id, status="running")
    session.add(job)
    await session.flush()

    handler = RETEST_HANDLERS.get(finding.check_id)
    if handler is None:
        job.status = "completed"
        job.result = "not_supported"
        job.error = (
            f"Single-finding retest isn't supported yet for check type {finding.check_id!r} — "
            "it needs either a fresh authenticated session or AI-assisted payload validation "
            "that this endpoint doesn't perform. Run a full rescan to re-verify it instead."
        )
        job.completed_at = datetime.now(timezone.utc)
    else:
        client = ScopedHttpClient(version_id=scan_run.version_id, scope_entries=scope_entries, db_session=session)
        try:
            outcome = await handler(finding, client)
        except Exception as exc:  # noqa: BLE001 — surfaced on the job, not swallowed
            job.status = "failed"
            job.result = "error"
            job.error = str(exc)
        else:
            if outcome is None:
                job.status = "failed"
                job.result = "error"
                job.error = "Could not reach the target to re-verify this finding."
            else:
                job.status = "completed"
                job.result = "still_vulnerable" if outcome.still_vulnerable else "fixed"
                job.request_raw = outcome.request_raw
                job.response_raw = outcome.response_raw
                if finding.retest_status not in _ANALYST_LOCKED_STATUSES:
                    finding.retest_status = "open" if outcome.still_vulnerable else "fixed"
        finally:
            # Real, live-found bug: this was only closed in the success
            # path — a handler exception left the underlying httpx
            # connection pool leaked on every failed retest, not just
            # the happy path.
            await client.aclose()
        job.completed_at = datetime.now(timezone.utc)

    await write_audit_log(
        session,
        user=user,
        action="finding.retest",
        resource_type="version",
        resource_id=scan_run.version_id,
        metadata={"finding_id": str(finding.id), "check_id": finding.check_id, "result": job.result},
    )
    await session.commit()
    await session.refresh(job)
    return job


@router.get("/findings/{finding_id}/retest-jobs", response_model=list[RetestJobOut])
async def list_retest_jobs(
    finding_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[RetestJob]:
    await get_finding_or_404(session, finding_id, user.org_id)
    result = await session.execute(
        select(RetestJob).where(RetestJob.finding_id == finding_id).order_by(RetestJob.created_at)
    )
    return list(result.scalars().all())
