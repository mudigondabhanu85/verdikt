import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.audit import AuditLogEntry
from app.models.finding import Finding
from app.models.organization import User
from app.models.project import Project, Version
from app.models.project_membership import ProjectMembership
from app.models.review_candidate import ReviewCandidate
from app.models.scan import ScanRun


async def accessible_project_ids(session: AsyncSession, user: User) -> list[uuid.UUID] | None:
    """For routes that list/aggregate across many Projects at once (the
    Projects list, the org dashboard rollup) rather than resolving one
    specific id — the single-resource `_check_project_access` below
    doesn't fit a query with no project_id to check yet.

    None means "no restriction" (org_admin) — every caller must treat
    None as "don't add a filter," never as "empty access," or an
    org_admin would silently see zero projects instead of all of them.
    """
    if user.role == "org_admin":
        return None
    result = await session.execute(
        select(ProjectMembership.project_id).where(ProjectMembership.user_id == user.id)
    )
    return list(result.scalars())


async def _check_project_access(session: AsyncSession, project_id: uuid.UUID, user: User) -> None:
    """org_admin always passes (see ProjectMembership's own docstring for
    why) — everyone else needs an explicit ProjectMembership row. Never
    raises 403: a project a user can't access reads exactly like one
    that doesn't exist, matching the org-mismatch case this replaces
    (see the 404s below), so a restricted user can't distinguish "wrong
    org" from "right org, not assigned" from "doesn't exist"."""
    if user.role == "org_admin":
        return
    result = await session.execute(
        select(ProjectMembership.id).where(
            ProjectMembership.user_id == user.id, ProjectMembership.project_id == project_id
        )
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")


async def get_project_or_404(session: AsyncSession, project_id: uuid.UUID, user: User) -> Project:
    project = await session.get(Project, project_id)
    if project is None or project.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    await _check_project_access(session, project_id, user)
    return project


async def get_version_or_404(session: AsyncSession, version_id: uuid.UUID, user: User) -> Version:
    result = await session.execute(
        select(Version).join(Project, Version.project_id == Project.id).where(
            Version.id == version_id, Project.org_id == user.org_id
        )
    )
    version = result.scalar_one_or_none()
    if version is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Version not found")
    await _check_project_access(session, version.project_id, user)
    return version


async def get_scan_run_or_404(session: AsyncSession, scan_run_id: uuid.UUID, user: User) -> ScanRun:
    result = await session.execute(
        select(ScanRun, Project.id)
        .join(Version, ScanRun.version_id == Version.id)
        .join(Project, Version.project_id == Project.id)
        .where(ScanRun.id == scan_run_id, Project.org_id == user.org_id)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan run not found")
    scan_run, project_id = row
    await _check_project_access(session, project_id, user)
    return scan_run


async def get_finding_or_404(session: AsyncSession, finding_id: uuid.UUID, user: User) -> Finding:
    result = await session.execute(
        select(Finding, Project.id)
        .join(ScanRun, Finding.scan_run_id == ScanRun.id)
        .join(Version, ScanRun.version_id == Version.id)
        .join(Project, Version.project_id == Project.id)
        .where(Finding.id == finding_id, Project.org_id == user.org_id)
        .options(selectinload(Finding.evidence))
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    finding, project_id = row
    await _check_project_access(session, project_id, user)
    return finding


async def get_review_candidate_or_404(
    session: AsyncSession, candidate_id: uuid.UUID, user: User
) -> ReviewCandidate:
    result = await session.execute(
        select(ReviewCandidate, Project.id)
        .join(ScanRun, ReviewCandidate.scan_run_id == ScanRun.id)
        .join(Version, ScanRun.version_id == Version.id)
        .join(Project, Version.project_id == Project.id)
        .where(ReviewCandidate.id == candidate_id, Project.org_id == user.org_id)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Review candidate not found")
    candidate, project_id = row
    await _check_project_access(session, project_id, user)
    return candidate


async def write_audit_log(
    session: AsyncSession,
    *,
    user: User,
    action: str,
    resource_type: str,
    resource_id: uuid.UUID,
    metadata: dict | None = None,
) -> None:
    """Records the CRUD-level audit trail (§1.3). Never pass credential
    secrets in `metadata` — only identifiers and non-sensitive context.
    """
    session.add(
        AuditLogEntry(
            org_id=user.org_id,
            user_id=user.id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            entry_metadata=metadata,
        )
    )
