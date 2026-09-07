import asyncio
import uuid
from collections import Counter
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.agents import task_registry
from app.agents.retest import _match_key, execute_retest
from app.agents.runner import execute_scan_run
from app.ai.budget import BudgetGuard
from app.ai.provider import resolve_provider_and_model
from app.api.deps import get_scan_run_or_404, get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.ai_provider_config import AIProviderConfig
from app.models.attack_chain import AttackChain
from app.models.finding import Finding
from app.models.organization import User
from app.models.project import Version
from app.models.scan import AgentJob, ScanRun
from app.models.target import Target
from app.reporting.csv_report import render_csv_report
from app.reporting.docx_report import render_docx_report
from app.reporting.executive_summary import generate_executive_summary
from app.reporting.html_report import render_html_report
from app.reporting.pdf_report import render_pdf_report
from app.reporting.screenshots import load_screenshots_by_finding
from app.schemas.attack_chain import AttackChainOut
from app.schemas.finding import FindingOut
from app.schemas.scan import AgentJobOut, ScanRunCreate, ScanRunDetail, ScanRunDiffOut, ScanRunOut

router = APIRouter(tags=["scans"])


async def _require_authorized_version(session: AsyncSession, version_id: uuid.UUID, org_id: uuid.UUID) -> Version:
    version = await get_version_or_404(session, version_id, org_id)
    await session.refresh(version, attribute_names=["authorization_records"])
    if not version.is_authorized:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "This Version has no authorization record — the §1 authorization gate "
            "requires at least one before any agent can run against its targets.",
        )
    return version


async def _require_at_least_one_target(session: AsyncSession, version_id: uuid.UUID) -> None:
    """Without a Target, recon has nothing to crawl and every agent
    'completes' near-instantly having done nothing — a scan that looks
    successful (status=completed) but found almost nothing, with no
    indication anything was misconfigured. Catch it up front instead."""
    target_result = await session.execute(select(Target.id).where(Target.version_id == version_id).limit(1))
    if target_result.first() is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "This Version has no target configured — add at least one target URL before running a scan.",
        )


async def _run_scan_cancellable(scan_run_id: uuid.UUID) -> None:
    # Registers *this* task (whichever one BackgroundTasks is actually
    # awaiting it in — real Starlette/Uvicorn runs it inside the same
    # task that handled the request; httpx's ASGITransport under test
    # awaits it directly too, deterministically before the POST call
    # returns) so app.agents.task_registry's cancel() can reach it. A
    # plain asyncio.create_task() instead of going through BackgroundTasks
    # was tried and reverted — it broke exactly that "already finished by
    # the time the POST returns" guarantee several tests rely on.
    task = asyncio.current_task()
    if task is not None:
        task_registry.register(scan_run_id, task)
    await execute_scan_run(scan_run_id)


async def _run_retest_cancellable(scan_run_id: uuid.UUID, prior_scan_run_id: uuid.UUID) -> None:
    task = asyncio.current_task()
    if task is not None:
        task_registry.register(scan_run_id, task)
    await execute_retest(scan_run_id, prior_scan_run_id)


async def _resolve_ai_provider_config_id(
    session: AsyncSession, org_id: uuid.UUID, payload: ScanRunCreate | None
) -> uuid.UUID | None:
    ai_provider_config_id = payload.ai_provider_config_id if payload else None
    if ai_provider_config_id is not None:
        config = await session.get(AIProviderConfig, ai_provider_config_id)
        if config is None or config.org_id != org_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "AI provider config not found")
    return ai_provider_config_id


@router.post("/versions/{version_id}/scan-runs", response_model=ScanRunOut, status_code=201)
async def create_scan_run(
    version_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    payload: ScanRunCreate | None = None,
    user: User = Depends(require_permission("scan", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> ScanRun:
    await _require_authorized_version(session, version_id, user.org_id)
    await _require_at_least_one_target(session, version_id)
    ai_provider_config_id = await _resolve_ai_provider_config_id(session, user.org_id, payload)

    scan_run = ScanRun(
        version_id=version_id,
        status="pending",
        requested_by=user.id,
        ai_provider_config_id=ai_provider_config_id,
    )
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

    background_tasks.add_task(_run_scan_cancellable, scan_run.id)
    return scan_run


@router.post(
    "/versions/{version_id}/scan-runs/{prior_scan_run_id}/retest",
    response_model=ScanRunOut,
    status_code=201,
)
async def retest_scan_run(
    version_id: uuid.UUID,
    prior_scan_run_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    payload: ScanRunCreate | None = None,
    user: User = Depends(require_permission("scan", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> ScanRun:
    """Re-runs the scan against the same Version and, once it completes,
    diffs the new findings against prior_scan_run_id's: a prior finding
    that still reproduces (same check_id + affected_endpoints) stays/
    becomes retest_status="open"; one that no longer reproduces becomes
    "fixed". Findings an analyst already marked "risk_accepted" or
    "false_positive_after_review" are left alone — a rescan doesn't get
    to silently override a human decision. See app.agents.retest.
    """
    await _require_authorized_version(session, version_id, user.org_id)
    await _require_at_least_one_target(session, version_id)
    prior = await get_scan_run_or_404(session, prior_scan_run_id, user.org_id)
    if prior.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Prior scan run not found for this version")

    ai_provider_config_id = await _resolve_ai_provider_config_id(session, user.org_id, payload)

    scan_run = ScanRun(
        version_id=version_id,
        status="pending",
        requested_by=user.id,
        ai_provider_config_id=ai_provider_config_id,
    )
    session.add(scan_run)
    await write_audit_log(
        session,
        user=user,
        action="scan.retest",
        resource_type="version",
        resource_id=version_id,
        metadata={"prior_scan_run_id": str(prior_scan_run_id)},
    )
    await session.commit()
    await session.refresh(scan_run)

    background_tasks.add_task(_run_retest_cancellable, scan_run.id, prior_scan_run_id)
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
        ai_provider_config_id=scan_run.ai_provider_config_id,
        agent_jobs=[AgentJobOut.model_validate(j) for j in jobs],
        finding_counts_by_severity={sev: counts.get(sev, 0) for sev in ("Critical", "High", "Medium", "Low")},
        tech_stack_fingerprint=scan_run.tech_stack_fingerprint,
    )


@router.get("/scan-runs/{scan_run_id}", response_model=ScanRunDetail)
async def get_scan_run(
    scan_run_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> ScanRunDetail:
    scan_run = await get_scan_run_or_404(session, scan_run_id, user.org_id)
    return await _scan_run_detail(session, scan_run)


@router.post("/scan-runs/{scan_run_id}/cancel", response_model=ScanRunOut)
async def cancel_scan_run(
    scan_run_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> ScanRun:
    scan_run = await get_scan_run_or_404(session, scan_run_id, user.org_id)
    if scan_run.status not in ("pending", "running"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Scan run is already {scan_run.status} — nothing to cancel.",
        )

    # Best-effort reach into the actual running task (see
    # app.agents.task_registry) — if the backend restarted since this
    # scan started, there's no in-process task left to cancel, but the
    # row itself is still stuck showing "running" and should still be
    # markable as cancelled directly.
    task_registry.cancel(scan_run_id)
    scan_run.status = "cancelled"
    scan_run.completed_at = datetime.now(timezone.utc)
    await write_audit_log(
        session,
        user=user,
        action="scan.cancel",
        resource_type="scan_run",
        resource_id=scan_run_id,
    )
    await session.commit()
    await session.refresh(scan_run)
    return scan_run


@router.delete("/scan-runs/{scan_run_id}", status_code=204)
async def delete_scan_run(
    scan_run_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    scan_run = await get_scan_run_or_404(session, scan_run_id, user.org_id)
    if scan_run.status in ("pending", "running"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Cancel this scan run before deleting it.",
        )
    await write_audit_log(
        session,
        user=user,
        action="scan.delete",
        resource_type="scan_run",
        resource_id=scan_run_id,
    )
    # Every dependent row (agent jobs, findings, evidence, review
    # candidates, attack chains, ...) cascades at the database level —
    # see alembic/versions/0018_scan_delete_cascade_and_vgs_finding_link.py.
    await session.delete(scan_run)
    await session.commit()


async def _list_findings(session: AsyncSession, scan_run_id: uuid.UUID) -> list[Finding]:
    result = await session.execute(
        select(Finding)
        .options(selectinload(Finding.evidence))
        .where(Finding.scan_run_id == scan_run_id)
        .order_by(Finding.cvss_score.desc())
    )
    return list(result.scalars().all())


async def _list_attack_chains(session: AsyncSession, scan_run_id: uuid.UUID) -> list[AttackChain]:
    result = await session.execute(
        select(AttackChain).where(AttackChain.scan_run_id == scan_run_id)
    )
    chains = list(result.scalars().unique().all())
    for chain in chains:
        await session.refresh(chain, attribute_names=["evidence"])
    return chains


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

    provider, ai_model = await resolve_provider_and_model(session, scan_run)
    guard = BudgetGuard(scan_run, session, provider)
    summary = await generate_executive_summary(
        scan_run=detail, findings=findings, budget_guard=guard, ai_model=ai_model
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
    attack_chains = await _list_attack_chains(session, scan_run_id)
    return {
        "scan_run": detail.model_dump(mode="json"),
        "executive_summary": executive_summary,
        "findings": [FindingOut.model_validate(f).model_dump(mode="json") for f in findings],
        "attack_chains": [AttackChainOut.model_validate(c).model_dump(mode="json") for c in attack_chains],
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
    screenshots = await load_screenshots_by_finding(findings)
    attack_chains = await _list_attack_chains(session, scan_run_id)
    return render_html_report(
        scan_run=detail,
        findings=findings,
        executive_summary=executive_summary,
        screenshots_by_finding_id=screenshots,
        attack_chains=attack_chains,
    )


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
    screenshots = await load_screenshots_by_finding(findings)
    attack_chains = await _list_attack_chains(session, scan_run_id)
    pdf_bytes = render_pdf_report(
        scan_run=detail,
        findings=findings,
        executive_summary=executive_summary,
        screenshots_by_finding_id=screenshots,
        attack_chains=attack_chains,
    )
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
    screenshots = await load_screenshots_by_finding(findings)
    attack_chains = await _list_attack_chains(session, scan_run_id)
    docx_bytes = render_docx_report(
        scan_run=detail,
        findings=findings,
        executive_summary=executive_summary,
        screenshots_by_finding_id=screenshots,
        attack_chains=attack_chains,
    )
    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="verdikt-report-{scan_run_id}.docx"'},
    )


@router.get("/scan-runs/{scan_run_id}/report.csv")
async def get_report_csv(
    scan_run_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    await get_scan_run_or_404(session, scan_run_id, user.org_id)
    findings = await _list_findings(session, scan_run_id)
    csv_text = render_csv_report(findings)
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="verdikt-report-{scan_run_id}.csv"'},
    )


@router.get("/scan-runs/{later_scan_run_id}/diff/{earlier_scan_run_id}", response_model=ScanRunDiffOut)
async def get_scan_run_diff(
    later_scan_run_id: uuid.UUID,
    earlier_scan_run_id: uuid.UUID,
    user: User = Depends(require_permission("scan", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> ScanRunDiffOut:
    """§8 diff report — what changed between two scan runs against the
    same Version. Matches findings the same way app.agents.retest's
    scan-level diff already does (check_id + affected_endpoints), so
    "fixed" here means exactly what flips a Finding.retest_status to
    "fixed" during a rescan — this endpoint doesn't introduce a second,
    subtly different notion of "fixed".
    """
    later = await get_scan_run_or_404(session, later_scan_run_id, user.org_id)
    earlier = await get_scan_run_or_404(session, earlier_scan_run_id, user.org_id)
    if later.version_id != earlier.version_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Both scan runs must belong to the same Version")

    earlier_findings = await _list_findings(session, earlier_scan_run_id)
    later_findings = await _list_findings(session, later_scan_run_id)
    earlier_keys = {_match_key(f) for f in earlier_findings}
    later_keys = {_match_key(f) for f in later_findings}

    new_findings = [f for f in later_findings if _match_key(f) not in earlier_keys]
    fixed_findings = [f for f in earlier_findings if _match_key(f) not in later_keys]
    still_open_findings = [f for f in later_findings if _match_key(f) in earlier_keys]

    return ScanRunDiffOut(
        earlier_scan_run_id=earlier_scan_run_id,
        later_scan_run_id=later_scan_run_id,
        new_findings=[FindingOut.model_validate(f) for f in new_findings],
        fixed_findings=[FindingOut.model_validate(f) for f in fixed_findings],
        still_open_findings=[FindingOut.model_validate(f) for f in still_open_findings],
    )
