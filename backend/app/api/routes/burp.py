import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_scan_run_or_404, get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.integrations.burp.mapping import map_issue_to_finding
from app.integrations.burp.rest_client import BurpRestClient, BurpScanError
from app.models.organization import User
from app.models.scan import AgentJob, ScanRun
from app.schemas.burp import BurpImportResult, BurpScanCreate, BurpScanCreated, BurpScanImport

router = APIRouter(prefix="/versions/{version_id}/burp", tags=["burp"])


@router.post("/scans", response_model=BurpScanCreated, status_code=201)
async def start_burp_scan(
    version_id: uuid.UUID,
    payload: BurpScanCreate,
    user: User = Depends(require_permission("scan", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> BurpScanCreated:
    """Triggers a scan on Burp Suite Professional's local Scanner REST API
    (§4/§11) and creates a dedicated ScanRun/AgentJob pair to track it —
    findings imported later (via /scans/{task_id}/import) land in this
    same ScanRun, so the existing report endpoints (§8) pick them up with
    no changes. Connection details (base URL, API key) are passed
    per-call, never persisted — avoids inventing a new stored-secret
    concept for one integration.
    """
    await get_version_or_404(session, version_id, user.org_id)

    scan_run = ScanRun(
        version_id=version_id,
        status="running",
        requested_by=user.id,
        started_at=datetime.now(timezone.utc),
    )
    session.add(scan_run)
    await session.flush()

    job = AgentJob(
        scan_run_id=scan_run.id,
        agent_type="burp_scan",
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    session.add(job)
    await session.flush()

    client = BurpRestClient(payload.burp_base_url, payload.burp_api_key)
    try:
        task_id = await client.start_scan(
            payload.urls, scan_configurations=payload.scan_configurations
        )
    except BurpScanError as exc:
        job.status = "failed"
        job.completed_at = datetime.now(timezone.utc)
        job.error = str(exc)
        scan_run.status = "failed"
        scan_run.error = str(exc)
        await session.commit()
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Could not start Burp scan: {exc}"
        ) from exc

    job.stats = {"burp_task_id": task_id, "urls": payload.urls}
    # Never audit the API key (§1.5) — only the scan target list and Burp task id.
    await write_audit_log(
        session,
        user=user,
        action="burp.scan_start",
        resource_type="version",
        resource_id=version_id,
        metadata={"task_id": task_id, "urls": payload.urls},
    )
    await session.commit()

    return BurpScanCreated(scan_run_id=scan_run.id, agent_job_id=job.id, task_id=task_id)


@router.post("/scans/{task_id}/import", response_model=BurpImportResult)
async def import_burp_scan(
    version_id: uuid.UUID,
    task_id: str,
    payload: BurpScanImport,
    user: User = Depends(require_permission("scan", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> BurpImportResult:
    """Polls the given Burp scan task until it reaches a terminal status,
    then maps every reported issue into a Finding (confirmation_status=
    "analyst_confirmed" — Burp already did its own detection/confirmation,
    see app.integrations.burp.mapping). Not our AI pipeline's §2
    Confirmed-Only Findings flow — a distinct, clearly-labeled import
    path, not a claim that our agents re-verified Burp's results.
    """
    await get_version_or_404(session, version_id, user.org_id)
    scan_run = await get_scan_run_or_404(session, payload.scan_run_id, user.org_id)
    if scan_run.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan run not found for this version")

    job = AgentJob(
        scan_run_id=scan_run.id,
        agent_type="burp_import",
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    session.add(job)
    await session.flush()

    client = BurpRestClient(payload.burp_base_url, payload.burp_api_key)
    try:
        status_body = await client.wait_for_completion(
            task_id, poll_interval=payload.poll_interval, timeout=payload.timeout
        )
    except BurpScanError as exc:
        job.status = "failed"
        job.completed_at = datetime.now(timezone.utc)
        job.error = str(exc)
        await session.commit()
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Could not import Burp scan: {exc}"
        ) from exc

    issues = client.extract_issues(status_body)
    finding_ids: list[uuid.UUID] = []
    for issue in issues:
        finding, evidence = map_issue_to_finding(
            issue, scan_run_id=scan_run.id, agent_job_id=job.id
        )
        session.add(finding)
        await session.flush()
        finding_ids.append(finding.id)
        if evidence is not None:
            evidence.finding_id = finding.id
            session.add(evidence)

    scan_status = status_body.get("scan_status", "unknown")
    job.status = "completed" if scan_status == "succeeded" else "failed"
    job.completed_at = datetime.now(timezone.utc)
    job.stats = {
        "burp_task_id": task_id,
        "scan_status": scan_status,
        "issues_imported": len(finding_ids),
    }

    await write_audit_log(
        session,
        user=user,
        action="burp.scan_import",
        resource_type="version",
        resource_id=version_id,
        metadata={"task_id": task_id, "imported_count": len(finding_ids)},
    )
    await session.commit()

    return BurpImportResult(
        scan_status=scan_status, imported_count=len(finding_ids), finding_ids=finding_ids
    )
