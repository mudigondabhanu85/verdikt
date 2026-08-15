import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLogEntry
from app.models.organization import User
from app.models.project import Project, Version


async def get_project_or_404(session: AsyncSession, project_id: uuid.UUID, org_id: uuid.UUID) -> Project:
    project = await session.get(Project, project_id)
    if project is None or project.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return project


async def get_version_or_404(session: AsyncSession, version_id: uuid.UUID, org_id: uuid.UUID) -> Version:
    result = await session.execute(
        select(Version).join(Project, Version.project_id == Project.id).where(
            Version.id == version_id, Project.org_id == org_id
        )
    )
    version = result.scalar_one_or_none()
    if version is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Version not found")
    return version


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
