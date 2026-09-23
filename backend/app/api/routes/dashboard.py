"""§8 reporting gap — an org-wide rollup: how many open findings by
severity across every project/version, and the most recently run scans.
No new aggregation tables — computed live from the same Finding/ScanRun/
Version/Project rows every other report already reads, since an org's
total finding count is nowhere near large enough to need pre-aggregation
for a first pass.
"""

from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import accessible_project_ids
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.finding import Finding
from app.models.organization import User
from app.models.project import Project, Version
from app.models.scan import ScanRun
from app.schemas.dashboard import DashboardOut, DashboardScanRunSummary

router = APIRouter(tags=["dashboard"])

_RECENT_SCAN_RUN_LIMIT = 10
_SEVERITIES = ("Critical", "High", "Medium", "Low")


@router.get("/organizations/me/dashboard", response_model=DashboardOut)
async def get_dashboard(
    user: User = Depends(require_permission("scan", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> DashboardOut:
    project_ids = await accessible_project_ids(session, user)
    project_filter = Project.org_id == user.org_id if project_ids is None else Project.id.in_(project_ids)

    total_projects = (
        await session.execute(select(func.count(Project.id)).where(project_filter))
    ).scalar_one()
    total_versions = (
        await session.execute(
            select(func.count(Version.id)).join(Project, Version.project_id == Project.id).where(project_filter)
        )
    ).scalar_one()
    total_scan_runs = (
        await session.execute(
            select(func.count(ScanRun.id))
            .join(Version, ScanRun.version_id == Version.id)
            .join(Project, Version.project_id == Project.id)
            .where(project_filter)
        )
    ).scalar_one()

    severity_rows = (
        await session.execute(
            select(Finding.severity, func.count(Finding.id))
            .join(ScanRun, Finding.scan_run_id == ScanRun.id)
            .join(Version, ScanRun.version_id == Version.id)
            .join(Project, Version.project_id == Project.id)
            .where(project_filter, Finding.retest_status != "fixed")
            .group_by(Finding.severity)
        )
    ).all()
    open_findings_by_severity = {sev: 0 for sev in _SEVERITIES}
    for severity, count in severity_rows:
        open_findings_by_severity[severity] = count

    recent_rows = (
        await session.execute(
            select(ScanRun, Version.name, Project.name)
            .join(Version, ScanRun.version_id == Version.id)
            .join(Project, Version.project_id == Project.id)
            .where(project_filter)
            .order_by(ScanRun.created_at.desc())
            .limit(_RECENT_SCAN_RUN_LIMIT)
        )
    ).all()

    recent_scan_run_ids = [scan_run.id for scan_run, _, _ in recent_rows]
    counts_by_scan_run: dict = defaultdict(lambda: {sev: 0 for sev in _SEVERITIES})
    if recent_scan_run_ids:
        finding_rows = (
            await session.execute(
                select(Finding.scan_run_id, Finding.severity, func.count(Finding.id))
                .where(Finding.scan_run_id.in_(recent_scan_run_ids))
                .group_by(Finding.scan_run_id, Finding.severity)
            )
        ).all()
        for scan_run_id, severity, count in finding_rows:
            counts_by_scan_run[scan_run_id][severity] = count

    recent_scan_runs = [
        DashboardScanRunSummary(
            id=scan_run.id,
            version_id=scan_run.version_id,
            project_name=project_name,
            version_name=version_name,
            status=scan_run.status,
            started_at=scan_run.started_at,
            completed_at=scan_run.completed_at,
            finding_counts_by_severity=dict(counts_by_scan_run[scan_run.id]),
        )
        for scan_run, version_name, project_name in recent_rows
    ]

    return DashboardOut(
        total_projects=total_projects,
        total_versions=total_versions,
        total_scan_runs=total_scan_runs,
        open_findings_by_severity=open_findings_by_severity,
        recent_scan_runs=recent_scan_runs,
    )
