import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.org_branding import OrgBranding
from app.models.organization import User
from app.models.vgs_vulnerability import (
    VgsEvidenceStep,
    VgsReportDraft,
    VgsReportVulnerability,
    VgsVulnerabilityLibraryEntry,
)
from app.reporting.html_report import BrandingInfo
from app.reporting.vgs_docx_report import render_vgs_docx_report
from app.schemas.vgs_vulnerability import (
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
    await get_version_or_404(session, version_id, user.org_id)
    return await _get_or_create_draft(session, version_id)


@draft_router.patch("", response_model=VgsReportDraftOut)
async def update_report_draft(
    version_id: uuid.UUID,
    payload: VgsReportDraftUpdate,
    user: User = Depends(require_permission("vgs_vulnerability", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> VgsReportDraft:
    await get_version_or_404(session, version_id, user.org_id)
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
    await get_version_or_404(session, version_id, user.org_id)
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


@draft_router.get("/vulnerabilities", response_model=list[VgsReportVulnerabilityOut])
async def list_report_vulnerabilities(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("vgs_vulnerability", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[VgsReportVulnerability]:
    await get_version_or_404(session, version_id, user.org_id)
    draft = await _get_or_create_draft(session, version_id)
    result = await session.execute(
        select(VgsReportVulnerability)
        .where(VgsReportVulnerability.report_draft_id == draft.id)
        .order_by(VgsReportVulnerability.order_index)
    )
    return list(result.scalars().all())


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
    await get_version_or_404(session, version_id, user.org_id)
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
    await get_version_or_404(session, version_id, user.org_id)
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
    await get_version_or_404(session, version_id, user.org_id)
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
    await get_version_or_404(session, version_id, user.org_id)
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
    await get_version_or_404(session, version_id, user.org_id)
    step = await _get_evidence_step_or_404(session, version_id, vuln_id, step_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(step, field, value)
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
    await get_version_or_404(session, version_id, user.org_id)
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
    await get_version_or_404(session, version_id, user.org_id)
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
