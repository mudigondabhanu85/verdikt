import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.integrations.portswigger.client import PortswigerFetchError, fetch_topics
from app.models.finding import Evidence, Finding
from app.models.org_branding import OrgBranding
from app.models.organization import User
from app.models.scan import ScanRun
from app.models.vgs_vulnerability import (
    VgsEvidenceStep,
    VgsReportDraft,
    VgsReportVulnerability,
    VgsVulnerabilityLibraryEntry,
)
from app.reporting.grouping import FindingGroup, group_findings
from app.reporting.html_report import BrandingInfo
from app.reporting.vgs_docx_report import (
    build_evidence_steps_for_group,
    build_vulnerability_from_group,
    render_vgs_docx_report,
)
from app.schemas.finding import FindingOut
from app.schemas.vgs_vulnerability import (
    AvailableFindingOut,
    PortswigerLoadResult,
    VgsEvidenceStepOut,
    VgsEvidenceStepUpdate,
    VgsReportDraftOut,
    VgsReportDraftUpdate,
    VgsReportVulnerabilityCreate,
    VgsReportVulnerabilityOut,
    VgsReportVulnerabilityUpdate,
    VgsVulnerabilityLibraryEntryCreate,
    VgsVulnerabilityLibraryEntryOut,
)
from app.storage.local_disk import get_object_storage

library_router = APIRouter(prefix="/vgs-vulnerability-library", tags=["vgs-report-builder"])
draft_router = APIRouter(prefix="/versions/{version_id}/vgs-report-draft", tags=["vgs-report-builder"])


# --- Library CRUD (org-scoped curated vulnerability library) ---------------


@library_router.post("", response_model=VgsVulnerabilityLibraryEntryOut, status_code=201)
async def create_library_entry(
    payload: VgsVulnerabilityLibraryEntryCreate,
    user: User = Depends(require_permission("vgs_vulnerability", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> VgsVulnerabilityLibraryEntry:
    entry = VgsVulnerabilityLibraryEntry(org_id=user.org_id, **payload.model_dump())
    session.add(entry)
    await write_audit_log(
        session,
        user=user,
        action="vgs_vulnerability_library.create",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"title": entry.title},
    )
    await session.commit()
    await session.refresh(entry)
    return entry


@library_router.get("", response_model=list[VgsVulnerabilityLibraryEntryOut])
async def list_library_entries(
    user: User = Depends(require_permission("vgs_vulnerability", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[VgsVulnerabilityLibraryEntry]:
    result = await session.execute(
        select(VgsVulnerabilityLibraryEntry).where(VgsVulnerabilityLibraryEntry.org_id == user.org_id)
    )
    return list(result.scalars().all())


async def _get_library_entry_or_404(
    session: AsyncSession, org_id: uuid.UUID, entry_id: uuid.UUID
) -> VgsVulnerabilityLibraryEntry:
    entry = await session.get(VgsVulnerabilityLibraryEntry, entry_id)
    if entry is None or entry.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Library entry not found")
    return entry


@library_router.patch("/{entry_id}", response_model=VgsVulnerabilityLibraryEntryOut)
async def update_library_entry(
    entry_id: uuid.UUID,
    payload: VgsVulnerabilityLibraryEntryCreate,
    user: User = Depends(require_permission("vgs_vulnerability", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> VgsVulnerabilityLibraryEntry:
    entry = await _get_library_entry_or_404(session, user.org_id, entry_id)
    for field, value in payload.model_dump().items():
        setattr(entry, field, value)
    await write_audit_log(
        session,
        user=user,
        action="vgs_vulnerability_library.update",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"title": entry.title},
    )
    await session.commit()
    await session.refresh(entry)
    return entry


@library_router.delete("/{entry_id}", status_code=204)
async def delete_library_entry(
    entry_id: uuid.UUID,
    user: User = Depends(require_permission("vgs_vulnerability", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    entry = await _get_library_entry_or_404(session, user.org_id, entry_id)
    await write_audit_log(
        session,
        user=user,
        action="vgs_vulnerability_library.delete",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"title": entry.title},
    )
    await session.delete(entry)
    await session.commit()


@library_router.post("/load-from-portswigger", response_model=PortswigerLoadResult)
async def load_library_from_portswigger(
    user: User = Depends(require_permission("vgs_vulnerability", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> PortswigerLoadResult:
    """One-click port of the standalone VGS tool's real workflow —
    scripts/portswigger_to_excel.py scrapes a fixed list of PortSwigger Web
    Security Academy topic pages into an Excel file, which Manage Vulns'
    upload_excel/ endpoint then upserts by title. Collapsed here into a
    single server-side action instead of the scrape-to-Excel-then-upload
    round trip, with the same upsert-by-title semantics."""
    try:
        topics = await fetch_topics()
    except PortswigerFetchError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc

    inserted = updated = skipped = 0
    for topic in topics:
        if not topic.title:
            skipped += 1
            continue
        existing_result = await session.execute(
            select(VgsVulnerabilityLibraryEntry).where(
                VgsVulnerabilityLibraryEntry.org_id == user.org_id,
                func.lower(VgsVulnerabilityLibraryEntry.title) == topic.title.lower(),
            )
        )
        existing = existing_result.scalar_one_or_none()
        if existing is not None:
            if existing.description != topic.description or existing.reference != topic.url:
                existing.description = topic.description
                existing.reference = topic.url
                updated += 1
            else:
                skipped += 1
        else:
            session.add(
                VgsVulnerabilityLibraryEntry(
                    org_id=user.org_id,
                    title=topic.title,
                    severity="Medium",
                    cvss_score="",
                    cvss_vector="",
                    description=topic.description,
                    recommendation="",
                    reference=topic.url,
                )
            )
            inserted += 1

    await write_audit_log(
        session,
        user=user,
        action="vgs_vulnerability_library.load_from_portswigger",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"inserted": inserted, "updated": updated, "skipped": skipped},
    )
    await session.commit()
    return PortswigerLoadResult(inserted=inserted, updated=updated, skipped=skipped)


# --- Report draft (one per Version) -----------------------------------------


async def _get_or_create_draft(session: AsyncSession, version_id: uuid.UUID) -> VgsReportDraft:
    result = await session.execute(select(VgsReportDraft).where(VgsReportDraft.version_id == version_id))
    draft = result.scalar_one_or_none()
    if draft is None:
        draft = VgsReportDraft(version_id=version_id)
        session.add(draft)
        await session.commit()
        await session.refresh(draft)
    return draft


@draft_router.get("", response_model=VgsReportDraftOut)
async def get_report_draft(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("vgs_vulnerability", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> VgsReportDraft:
    await get_version_or_404(session, version_id, user)
    return await _get_or_create_draft(session, version_id)


@draft_router.patch("", response_model=VgsReportDraftOut)
async def update_report_draft(
    version_id: uuid.UUID,
    payload: VgsReportDraftUpdate,
    user: User = Depends(require_permission("vgs_vulnerability", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> VgsReportDraft:
    await get_version_or_404(session, version_id, user)
    draft = await _get_or_create_draft(session, version_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(draft, field, value)
    await write_audit_log(
        session,
        user=user,
        action="vgs_report_draft.update",
        resource_type="version",
        resource_id=version_id,
        metadata={},
    )
    await session.commit()
    await session.refresh(draft)
    return draft


# --- Selected vulnerabilities within a draft --------------------------------


@draft_router.post("/vulnerabilities", response_model=VgsReportVulnerabilityOut, status_code=201)
async def add_report_vulnerability(
    version_id: uuid.UUID,
    payload: VgsReportVulnerabilityCreate,
    user: User = Depends(require_permission("vgs_vulnerability", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> VgsReportVulnerability:
    await get_version_or_404(session, version_id, user)
    draft = await _get_or_create_draft(session, version_id)

    if payload.library_entry_id is not None:
        source = await _get_library_entry_or_404(session, user.org_id, payload.library_entry_id)
        fields = {
            "title": source.title,
            "severity": source.severity,
            "cvss_score": source.cvss_score,
            "cvss_vector": source.cvss_vector,
            "description": source.description,
            "recommendation": source.recommendation,
            "reference": source.reference,
        }
    else:
        if not payload.title or not payload.severity:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "An ad-hoc vulnerability requires at least title and severity.",
            )
        fields = {
            "title": payload.title,
            "severity": payload.severity,
            "cvss_score": payload.cvss_score,
            "cvss_vector": payload.cvss_vector,
            "description": payload.description,
            "recommendation": payload.recommendation,
            "reference": payload.reference,
        }

    count_result = await session.execute(
        select(VgsReportVulnerability).where(VgsReportVulnerability.report_draft_id == draft.id)
    )
    order_index = len(list(count_result.scalars().all()))

    vuln = VgsReportVulnerability(
        report_draft_id=draft.id,
        library_entry_id=payload.library_entry_id,
        order_index=order_index,
        **fields,
    )
    session.add(vuln)
    await write_audit_log(
        session,
        user=user,
        action="vgs_report_vulnerability.add",
        resource_type="version",
        resource_id=version_id,
        metadata={"title": vuln.title, "from_library": payload.library_entry_id is not None},
    )
    await session.commit()
    await session.refresh(vuln)
    return vuln


async def _attach_finding_evidence(
    session: AsyncSession, vuln: VgsReportVulnerability, group: FindingGroup
) -> None:
    instance_ids = [instance.id for instance in group.detailed_instances]
    evidence_result = await session.execute(select(Evidence).where(Evidence.finding_id.in_(instance_ids)))
    evidence_by_finding_id = {evidence.finding_id: evidence for evidence in evidence_result.scalars().all()}

    for step in build_evidence_steps_for_group(vuln.id, group, evidence_by_finding_id):
        session.add(step)


async def _group_open_findings_for_version(session: AsyncSession, version_id: uuid.UUID) -> list[FindingGroup]:
    scan_run_ids_result = await session.execute(
        select(ScanRun.id).where(ScanRun.version_id == version_id)
    )
    scan_run_ids = [row[0] for row in scan_run_ids_result.all()]
    if not scan_run_ids:
        return []
    findings_result = await session.execute(
        select(Finding)
        .options(selectinload(Finding.evidence))
        .where(
            Finding.scan_run_id.in_(scan_run_ids),
            Finding.retest_status.in_(("open", "risk_accepted")),
        )
        .order_by(Finding.cvss_score.desc())
    )
    return group_findings(list(findings_result.scalars().all()))


async def _auto_seed_findings_into_draft(
    session: AsyncSession, version_id: uuid.UUID, draft: VgsReportDraft
) -> None:
    """Every real open/risk-accepted scan finding for this Version is
    auto-added — one report vulnerability per (check_id, title) group,
    not per raw Finding row (see _build_vulnerability_from_group) — so a
    report starts pre-populated with what the scan actually found, and
    curation from there is by removing what you don't want.

    Runs on every list_report_vulnerabilities call, not just the first
    (findings_auto_seeded now only records "has this draft ever been
    seeded at least once" for informational purposes) — a real gap this
    closes: a later scan run confirming a vulnerability class this
    draft had never seen before (a real incident: a vertical-privilege-
    escalation check added after this version's draft already existed)
    was invisible in "Selected for this report" until an analyst
    happened to notice it in the Vulnerability Picker's "From scans"
    list and added it by hand — a scan-confirmed finding should show up
    in the VGS tab as a matter of course, not by luck. Safe to re-run:
    the `already_ids` check below only ever adds a group whose
    representative Finding isn't already linked as some row's
    source_finding_id in this draft, so an existing, still-present
    selection is never duplicated. A vulnerability an analyst
    deliberately removed *will* reappear if a later scan reconfirms the
    same (check_id, title) group — matching "whatever the scan finds
    shows up here" rather than silently trusting a stale removal
    decision made before that later scan ever ran.
    """
    groups = await _group_open_findings_for_version(session, version_id)

    if groups:
        already_present_result = await session.execute(
            select(VgsReportVulnerability.source_finding_id).where(
                VgsReportVulnerability.report_draft_id == draft.id,
                VgsReportVulnerability.source_finding_id.isnot(None),
            )
        )
        already_present_ids = {str(row[0]) for row in already_present_result.all()}
        ever_seeded_ids = set(draft.auto_seeded_finding_ids or [])
        skip_ids = already_present_ids | ever_seeded_ids

        count_result = await session.execute(
            select(VgsReportVulnerability).where(VgsReportVulnerability.report_draft_id == draft.id)
        )
        order_index = len(list(count_result.scalars().all()))

        for group in groups:
            if any(str(finding.id) in skip_ids for finding in group.instances):
                continue
            vuln = build_vulnerability_from_group(draft.id, group, order_index)
            order_index += 1
            session.add(vuln)
            await session.flush()
            await _attach_finding_evidence(session, vuln, group)
            _mark_group_as_seeded(draft, group)

    draft.findings_auto_seeded = True
    await session.commit()


def _mark_group_as_seeded(draft: VgsReportDraft, group: FindingGroup) -> None:
    """Records every Finding.id in this group as having been offered to
    this draft at least once — auto-seed's persistent memory against
    resurrecting a deliberately-deleted vulnerability the next time it
    runs (see VgsReportDraft.auto_seeded_finding_ids). Called both by
    auto-seed itself and by the manual per-finding "Add" action, so a
    manual add is remembered exactly the same way an automatic one is —
    otherwise deleting a manually-added vulnerability would have
    auto-seed immediately resurrect it on the very next Picker load.
    """
    seen = set(draft.auto_seeded_finding_ids or [])
    seen.update(str(finding.id) for finding in group.instances)
    draft.auto_seeded_finding_ids = sorted(seen)


@draft_router.get("/vulnerabilities", response_model=list[VgsReportVulnerabilityOut])
async def list_report_vulnerabilities(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("vgs_vulnerability", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[VgsReportVulnerability]:
    await get_version_or_404(session, version_id, user)
    draft = await _get_or_create_draft(session, version_id)
    await _auto_seed_findings_into_draft(session, version_id, draft)
    result = await session.execute(
        select(VgsReportVulnerability)
        .where(VgsReportVulnerability.report_draft_id == draft.id)
        .order_by(VgsReportVulnerability.order_index)
    )
    return list(result.scalars().all())


@draft_router.get("/available-findings", response_model=list[AvailableFindingOut])
async def list_available_findings(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("vgs_vulnerability", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[AvailableFindingOut]:
    """Every real, scan-confirmed vulnerability class for this Version —
    across all of its scan runs, not just the latest — so the
    Vulnerability Picker can offer what the scanner actually found
    alongside the curated library. One row per (check_id, title) group,
    not per raw Finding instance (see _group_open_findings_for_version) —
    a check confirmed on hundreds of endpoints is one entry here, with
    every affected endpoint folded into affected_endpoints, not hundreds
    of near-duplicate rows. Excludes findings already retested as fixed
    or dismissed as a false positive; a group already added to this draft
    is flagged via already_added rather than hidden, so re-adding is a
    deliberate choice."""
    await get_version_or_404(session, version_id, user)
    draft = await _get_or_create_draft(session, version_id)

    groups = await _group_open_findings_for_version(session, version_id)
    if not groups:
        return []

    added_result = await session.execute(
        select(VgsReportVulnerability.source_finding_id).where(
            VgsReportVulnerability.report_draft_id == draft.id,
            VgsReportVulnerability.source_finding_id.isnot(None),
        )
    )
    already_added_ids = {row[0] for row in added_result.all()}

    result = []
    for group in groups:
        representative = group.shared
        all_endpoints = sorted({ep for finding in group.instances for ep in finding.affected_endpoints})
        finding_out = FindingOut.model_validate(representative).model_copy(
            update={"affected_endpoints": all_endpoints}
        )
        result.append(
            AvailableFindingOut(
                finding=finding_out,
                scan_run_id=representative.scan_run_id,
                already_added=any(finding.id in already_added_ids for finding in group.instances),
            )
        )
    return result


@draft_router.post(
    "/vulnerabilities/from-finding/{finding_id}",
    response_model=VgsReportVulnerabilityOut,
    status_code=201,
)
async def add_report_vulnerability_from_finding(
    version_id: uuid.UUID,
    finding_id: uuid.UUID,
    user: User = Depends(require_permission("vgs_vulnerability", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> VgsReportVulnerability:
    await get_version_or_404(session, version_id, user)
    draft = await _get_or_create_draft(session, version_id)

    finding = await session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    scan_run = await session.get(ScanRun, finding.scan_run_id)
    if scan_run is None or scan_run.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")

    # The picker offers one row per (check_id, title) group (see
    # list_available_findings) — resolve finding_id (the group's
    # representative id) back to its full group so every affected
    # endpoint is captured, not just this one instance. Falls back to a
    # single-instance group if the finding fell out of the open/
    # risk-accepted set between listing and adding.
    groups = await _group_open_findings_for_version(session, version_id)
    group = next(
        (g for g in groups if any(instance.id == finding.id for instance in g.instances)), None
    )
    if group is None:
        group = FindingGroup(
            check_id=finding.check_id, title=finding.title, severity=finding.severity, instances=[finding]
        )

    count_result = await session.execute(
        select(VgsReportVulnerability).where(VgsReportVulnerability.report_draft_id == draft.id)
    )
    order_index = len(list(count_result.scalars().all()))

    vuln = build_vulnerability_from_group(draft.id, group, order_index)
    session.add(vuln)
    await session.flush()
    await _attach_finding_evidence(session, vuln, group)
    _mark_group_as_seeded(draft, group)

    await write_audit_log(
        session,
        user=user,
        action="vgs_report_vulnerability.add_from_finding",
        resource_type="version",
        resource_id=version_id,
        metadata={"title": vuln.title, "finding_id": str(finding.id)},
    )
    await session.commit()
    await session.refresh(vuln)
    return vuln


async def _get_report_vulnerability_or_404(
    session: AsyncSession, version_id: uuid.UUID, vuln_id: uuid.UUID
) -> VgsReportVulnerability:
    vuln = await session.get(VgsReportVulnerability, vuln_id)
    if vuln is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Selected vulnerability not found")
    draft = await session.get(VgsReportDraft, vuln.report_draft_id)
    if draft is None or draft.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Selected vulnerability not found")
    return vuln


@draft_router.patch("/vulnerabilities/{vuln_id}", response_model=VgsReportVulnerabilityOut)
async def update_report_vulnerability(
    version_id: uuid.UUID,
    vuln_id: uuid.UUID,
    payload: VgsReportVulnerabilityUpdate,
    user: User = Depends(require_permission("vgs_vulnerability", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> VgsReportVulnerability:
    await get_version_or_404(session, version_id, user)
    vuln = await _get_report_vulnerability_or_404(session, version_id, vuln_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(vuln, field, value)
    await write_audit_log(
        session,
        user=user,
        action="vgs_report_vulnerability.update",
        resource_type="version",
        resource_id=version_id,
        metadata={"vuln_id": str(vuln_id)},
    )
    await session.commit()
    await session.refresh(vuln)
    return vuln


@draft_router.delete("/vulnerabilities/{vuln_id}", status_code=204)
async def delete_report_vulnerability(
    version_id: uuid.UUID,
    vuln_id: uuid.UUID,
    user: User = Depends(require_permission("vgs_vulnerability", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    await get_version_or_404(session, version_id, user)
    vuln = await _get_report_vulnerability_or_404(session, version_id, vuln_id)
    await write_audit_log(
        session,
        user=user,
        action="vgs_report_vulnerability.delete",
        resource_type="version",
        resource_id=version_id,
        metadata={"title": vuln.title},
    )
    await session.delete(vuln)
    await session.commit()


# --- Evidence steps within a selected vulnerability -------------------------


@draft_router.post(
    "/vulnerabilities/{vuln_id}/evidence-steps", response_model=VgsEvidenceStepOut, status_code=201
)
async def add_evidence_step(
    version_id: uuid.UUID,
    vuln_id: uuid.UUID,
    comment: str = "",
    screenshot: UploadFile | None = File(None),
    user: User = Depends(require_permission("vgs_vulnerability", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> VgsEvidenceStep:
    await get_version_or_404(session, version_id, user)
    await _get_report_vulnerability_or_404(session, version_id, vuln_id)

    screenshot_object_keys: list[str] = []
    if screenshot is not None:
        object_key = f"vgs-evidence/{vuln_id}/{uuid.uuid4().hex}-{screenshot.filename}"
        await get_object_storage().put(object_key, await screenshot.read())
        screenshot_object_keys = [object_key]

    count_result = await session.execute(
        select(VgsEvidenceStep).where(VgsEvidenceStep.report_vulnerability_id == vuln_id)
    )
    step_order = len(list(count_result.scalars().all()))

    step = VgsEvidenceStep(
        report_vulnerability_id=vuln_id,
        step_order=step_order,
        comment=comment,
        screenshot_object_keys=screenshot_object_keys,
    )
    session.add(step)
    await write_audit_log(
        session,
        user=user,
        action="vgs_evidence_step.add",
        resource_type="version",
        resource_id=version_id,
        metadata={"vuln_id": str(vuln_id)},
    )
    await session.commit()
    await session.refresh(step)
    return step


@draft_router.get(
    "/vulnerabilities/{vuln_id}/evidence-steps", response_model=list[VgsEvidenceStepOut]
)
async def list_evidence_steps(
    version_id: uuid.UUID,
    vuln_id: uuid.UUID,
    user: User = Depends(require_permission("vgs_vulnerability", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[VgsEvidenceStep]:
    await get_version_or_404(session, version_id, user)
    await _get_report_vulnerability_or_404(session, version_id, vuln_id)
    result = await session.execute(
        select(VgsEvidenceStep)
        .where(VgsEvidenceStep.report_vulnerability_id == vuln_id)
        .order_by(VgsEvidenceStep.step_order)
    )
    return list(result.scalars().all())


async def _get_evidence_step_or_404(
    session: AsyncSession, version_id: uuid.UUID, vuln_id: uuid.UUID, step_id: uuid.UUID
) -> VgsEvidenceStep:
    await _get_report_vulnerability_or_404(session, version_id, vuln_id)
    step = await session.get(VgsEvidenceStep, step_id)
    if step is None or step.report_vulnerability_id != vuln_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Evidence step not found")
    return step


@draft_router.patch(
    "/vulnerabilities/{vuln_id}/evidence-steps/{step_id}", response_model=VgsEvidenceStepOut
)
async def update_evidence_step(
    version_id: uuid.UUID,
    vuln_id: uuid.UUID,
    step_id: uuid.UUID,
    payload: VgsEvidenceStepUpdate,
    user: User = Depends(require_permission("vgs_vulnerability", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> VgsEvidenceStep:
    await get_version_or_404(session, version_id, user)
    step = await _get_evidence_step_or_404(session, version_id, vuln_id, step_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(step, field, value)
    await session.commit()
    await session.refresh(step)
    return step


@draft_router.post(
    "/vulnerabilities/{vuln_id}/evidence-steps/{step_id}/screenshots",
    response_model=VgsEvidenceStepOut,
    status_code=201,
)
async def add_evidence_step_screenshot(
    version_id: uuid.UUID,
    vuln_id: uuid.UUID,
    step_id: uuid.UUID,
    screenshot: UploadFile = File(...),
    user: User = Depends(require_permission("vgs_vulnerability", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> VgsEvidenceStep:
    """Appends a screenshot to an existing step — the real VGS
    EvidenceEditor's per-step 'Add Image' button lets an analyst attach a
    screenshot to any step at any time, not just when first creating it;
    the original add_evidence_step endpoint above only covered creation."""
    await get_version_or_404(session, version_id, user)
    step = await _get_evidence_step_or_404(session, version_id, vuln_id, step_id)

    object_key = f"vgs-evidence/{vuln_id}/{uuid.uuid4().hex}-{screenshot.filename}"
    await get_object_storage().put(object_key, await screenshot.read())
    step.screenshot_object_keys = [*step.screenshot_object_keys, object_key]

    await write_audit_log(
        session,
        user=user,
        action="vgs_evidence_step.add_screenshot",
        resource_type="version",
        resource_id=version_id,
        metadata={"vuln_id": str(vuln_id), "step_id": str(step_id)},
    )
    await session.commit()
    await session.refresh(step)
    return step


@draft_router.delete("/vulnerabilities/{vuln_id}/evidence-steps/{step_id}", status_code=204)
async def delete_evidence_step(
    version_id: uuid.UUID,
    vuln_id: uuid.UUID,
    step_id: uuid.UUID,
    user: User = Depends(require_permission("vgs_vulnerability", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    await get_version_or_404(session, version_id, user)
    step = await _get_evidence_step_or_404(session, version_id, vuln_id, step_id)
    await session.delete(step)
    await session.commit()


# --- Report generation -------------------------------------------------


@draft_router.get("/report.docx")
async def get_vgs_report_docx(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("vgs_vulnerability", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    await get_version_or_404(session, version_id, user)
    draft = await _get_or_create_draft(session, version_id)

    result = await session.execute(
        select(VgsReportVulnerability)
        .where(VgsReportVulnerability.report_draft_id == draft.id)
        .order_by(VgsReportVulnerability.order_index)
    )
    vulnerabilities = list(result.scalars().all())

    evidence_steps_by_vuln_id: dict[uuid.UUID, list[VgsEvidenceStep]] = {}
    screenshot_object_keys: set[str] = set()
    for vuln in vulnerabilities:
        steps_result = await session.execute(
            select(VgsEvidenceStep)
            .where(VgsEvidenceStep.report_vulnerability_id == vuln.id)
            .order_by(VgsEvidenceStep.step_order)
        )
        steps = list(steps_result.scalars().all())
        evidence_steps_by_vuln_id[vuln.id] = steps
        for step in steps:
            screenshot_object_keys.update(step.screenshot_object_keys)

    storage = get_object_storage()
    screenshot_bytes_by_object_key: dict[str, bytes] = {}
    for key in screenshot_object_keys:
        try:
            screenshot_bytes_by_object_key[key] = await storage.get(key)
        except OSError:
            continue

    branding_result = await session.execute(
        select(OrgBranding).where(OrgBranding.org_id == user.org_id)
    )
    org_branding = branding_result.scalar_one_or_none()
    branding = None
    if org_branding is not None:
        logo_bytes = None
        if org_branding.logo_object_key:
            try:
                logo_bytes = await storage.get(org_branding.logo_object_key)
            except OSError:
                logo_bytes = None
        branding = BrandingInfo(
            company_name=org_branding.company_name,
            primary_color_hex=org_branding.primary_color_hex,
            logo_bytes=logo_bytes,
        )

    docx_bytes = render_vgs_docx_report(
        draft=draft,
        vulnerabilities=vulnerabilities,
        evidence_steps_by_vuln_id=evidence_steps_by_vuln_id,
        screenshot_bytes_by_object_key=screenshot_bytes_by_object_key,
        branding=branding,
    )
    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="DVA_Report_{version_id}.docx"'},
    )
