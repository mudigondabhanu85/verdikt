import uuid
from collections import Counter
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.agents.runner import execute_scan_run
from app.ai.budget import BudgetGuard
from app.ai.provider import get_ai_provider
from app.api.deps import get_scan_run_or_404, get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.config import get_settings
from app.db.session import get_db_session
from app.models.finding import Finding
from app.models.organization import User
from app.models.scan import AgentJob, ScanRun
from app.reporting.docx_report import render_docx_report
from app.reporting.executive_summary import generate_executive_summary
from app.reporting.html_report import render_html_report
from app.reporting.pdf_report import render_pdf_report
from app.schemas.finding import FindingOut
from app.schemas.scan import AgentJobOut, ScanRunDetail, ScanRunOut

router = APIRouter(tags=["scans"])


@router.post("/versions/{version_id}/scan-runs", response_model=ScanRunOut, status_code=201)
async def create_scan_run(
    version_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    user: User = Depends(require_permission("scan", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> ScanRun:
    version = await get_version_or_404(session, version_id, user.org_id)
    await session.refresh(version, attribute_names=["authorization_records"])
    if not version.is_authorized:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "This Version has no authorization record — the §1 authorization gate "
            "requires at least one before any agent can run against its targets.",
        )

    scan_run = ScanRun(version_id=version_id, status="pending", requested_by=user.id)
    session.add(scan_run)
    await write_audit_log(
        session,
        user=user,
        action="scan.create",
        resource_type="version",
        resource_id=version_id,
    )
    await session.commit()
    await session.refresh(scan_run)

    background_tasks.add_task(execute_scan_run, scan_run.id)
    return scan_run


@router.get("/versions/{version_id}/scan-runs", response_model=list[ScanRunOut])
async def list_scan_runs(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[ScanRun]:
    await get_version_or_404(session, version_id, user.org_id)
    result = await session.execute(
        select(ScanRun).where(ScanRun.version_id == version_id).order_by(ScanRun.created_at.desc())
    )
    return list(result.scalars().all())


async def _scan_run_detail(session: AsyncSession, scan_run: ScanRun) -> ScanRunDetail:
    jobs = list(
        (
            await session.execute(select(AgentJob).where(AgentJob.scan_run_id == scan_run.id))
        ).scalars()
    )
    findings = list(
        (
            await session.execute(select(Finding).where(Finding.scan_run_id == scan_run.id))
        ).scalars()
    )
    counts = Counter(f.severity for f in findings)
    return ScanRunDetail(
        id=scan_run.id,
        version_id=scan_run.version_id,
        status=scan_run.status,
        started_at=scan_run.started_at,
        completed_at=scan_run.completed_at,
        error=scan_run.error,
        agent_jobs=[AgentJobOut.model_validate(j) for j in jobs],
        finding_counts_by_severity={sev: counts.get(sev, 0) for sev in ("Critical", "High", "Medium", "Low")},
    )


@router.get("/scan-runs/{scan_run_id}", response_model=ScanRunDetail)
async def get_scan_run(
    scan_run_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> ScanRunDetail:
    scan_run = await get_scan_run_or_404(session, scan_run_id, user.org_id)
    return await _scan_run_detail(session, scan_run)


async def _list_findings(session: AsyncSession, scan_run_id: uuid.UUID) -> list[Finding]:
    result = await session.execute(
        select(Finding)
        .options(selectinload(Finding.evidence))
        .where(Finding.scan_run_id == scan_run_id)
        .order_by(Finding.cvss_score.desc())
    )
    return list(result.scalars().all())


@router.get("/scan-runs/{scan_run_id}/findings", response_model=list[FindingOut])
async def list_findings(
    scan_run_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[Finding]:
    await get_scan_run_or_404(session, scan_run_id, user.org_id)
    return await _list_findings(session, scan_run_id)


async def _get_or_generate_executive_summary(
    session: AsyncSession, scan_run: ScanRun, detail: ScanRunDetail, findings: list[Finding]
) -> str:
    """Generated once per scan run and cached on ScanRun.executive_summary
    (§8/§10.5) — every report.json/html/pdf/docx request after the first
    reuses it instead of re-spending LLM budget on the same text."""
    if scan_run.executive_summary:
        return scan_run.executive_summary

    guard = BudgetGuard(scan_run, session, get_ai_provider())
    summary = await generate_executive_summary(
        scan_run=detail, findings=findings, budget_guard=guard, ai_model=get_settings().ai_model
    )
    scan_run.executive_summary = summary
    await session.commit()
    return summary


@router.get("/scan-runs/{scan_run_id}/report.json")
async def get_report_json(
    scan_run_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    scan_run = await get_scan_run_or_404(session, scan_run_id, user.org_id)
    detail = await _scan_run_detail(session, scan_run)
    findings = await _list_findings(session, scan_run_id)
    executive_summary = await _get_or_generate_executive_summary(session, scan_run, detail, findings)
    return {
        "scan_run": detail.model_dump(mode="json"),
        "executive_summary": executive_summary,
        "findings": [FindingOut.model_validate(f).model_dump(mode="json") for f in findings],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/scan-runs/{scan_run_id}/report.html", response_class=HTMLResponse)
async def get_report_html(
    scan_run_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> str:
    scan_run = await get_scan_run_or_404(session, scan_run_id, user.org_id)
    detail = await _scan_run_detail(session, scan_run)
    findings = await _list_findings(session, scan_run_id)
    executive_summary = await _get_or_generate_executive_summary(session, scan_run, detail, findings)
    return render_html_report(scan_run=detail, findings=findings, executive_summary=executive_summary)


@router.get("/scan-runs/{scan_run_id}/report.pdf")
async def get_report_pdf(
    scan_run_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    scan_run = await get_scan_run_or_404(session, scan_run_id, user.org_id)
    detail = await _scan_run_detail(session, scan_run)
    findings = await _list_findings(session, scan_run_id)
    executive_summary = await _get_or_generate_executive_summary(session, scan_run, detail, findings)
    pdf_bytes = render_pdf_report(scan_run=detail, findings=findings, executive_summary=executive_summary)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="verdikt-report-{scan_run_id}.pdf"'},
    )


@router.get("/scan-runs/{scan_run_id}/report.docx")
async def get_report_docx(
    scan_run_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    scan_run = await get_scan_run_or_404(session, scan_run_id, user.org_id)
    detail = await _scan_run_detail(session, scan_run)
    findings = await _list_findings(session, scan_run_id)
    executive_summary = await _get_or_generate_executive_summary(session, scan_run, detail, findings)
    docx_bytes = render_docx_report(scan_run=detail, findings=findings, executive_summary=executive_summary)
    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="verdikt-report-{scan_run_id}.docx"'},
    )
