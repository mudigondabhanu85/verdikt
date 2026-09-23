import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_project_or_404, get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.credential import CredentialSet
from app.models.organization import User
from app.models.project import ScopeEntry, Version
from app.schemas.version import (
    ScopeEntryCreate,
    ScopeEntryOut,
    ScopeEntryUpdate,
    VersionCreate,
    VersionOut,
)

router = APIRouter(tags=["versions"])


@router.post("/projects/{project_id}/versions", response_model=VersionOut, status_code=201)
async def create_version(
    project_id: uuid.UUID,
    payload: VersionCreate,
    user: User = Depends(require_permission("version", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> Version:
    await get_project_or_404(session, project_id, user)
    version = Version(project_id=project_id, name=payload.name, created_by=user.id)
    session.add(version)
    await session.flush()

    # Credential carry-forward (§5/§6): a new Version's credential sets
    # default to copies of the project's most recent prior Version, so a
    # re-engagement doesn't start from zero credentials. Copies, not
    # shared rows — editing the new version's copy (PATCH, credentials.py)
    # must never mutate the old version's historical record.
    prior_version_result = await session.execute(
        select(Version)
        .where(Version.project_id == project_id, Version.id != version.id)
        .order_by(Version.created_at.desc())
        .limit(1)
    )
    prior_version = prior_version_result.scalar_one_or_none()
    if prior_version is not None:
        prior_credentials_result = await session.execute(
            select(CredentialSet).where(CredentialSet.version_id == prior_version.id)
        )
        for prior in prior_credentials_result.scalars().all():
            session.add(
                CredentialSet(
                    version_id=version.id,
                    label=prior.label,
                    credential_type=prior.credential_type,
                    encrypted_secret=prior.encrypted_secret,
                    masked_reference=prior.masked_reference,
                    login_endpoint=prior.login_endpoint,
                    login_method=prior.login_method,
                    login_body_template=prior.login_body_template,
                    login_content_type=prior.login_content_type,
                    token_response_path=prior.token_response_path,
                    extra_cookies=prior.extra_cookies,
                )
            )

    await session.commit()
    await session.refresh(version)
    return version


@router.get("/projects/{project_id}/versions", response_model=list[VersionOut])
async def list_versions(
    project_id: uuid.UUID,
    user: User = Depends(require_permission("version", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[Version]:
    await get_project_or_404(session, project_id, user)
    result = await session.execute(
        select(Version)
        .where(Version.project_id == project_id)
        .order_by(Version.created_at)
    )
    return list(result.scalars().unique().all())


@router.get("/versions/{version_id}", response_model=VersionOut)
async def get_version(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("version", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> Version:
    return await get_version_or_404(session, version_id, user)


@router.post(
    "/versions/{version_id}/scope-entries", response_model=ScopeEntryOut, status_code=201
)
async def add_scope_entry(
    version_id: uuid.UUID,
    payload: ScopeEntryCreate,
    user: User = Depends(require_permission("version", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> ScopeEntry:
    await get_version_or_404(session, version_id, user)
    entry = ScopeEntry(version_id=version_id, **payload.model_dump())
    session.add(entry)
    await write_audit_log(
        session,
        user=user,
        action="scope_entry.create",
        resource_type="version",
        resource_id=version_id,
        metadata={"host": entry.host, "in_scope": entry.in_scope},
    )
    await session.commit()
    await session.refresh(entry)
    return entry


@router.get("/versions/{version_id}/scope-entries", response_model=list[ScopeEntryOut])
async def list_scope_entries(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("version", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[ScopeEntry]:
    await get_version_or_404(session, version_id, user)
    result = await session.execute(select(ScopeEntry).where(ScopeEntry.version_id == version_id))
    return list(result.scalars().all())


async def _get_scope_entry_or_404(
    session: AsyncSession, version_id: uuid.UUID, scope_entry_id: uuid.UUID
) -> ScopeEntry:
    entry = await session.get(ScopeEntry, scope_entry_id)
    if entry is None or entry.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scope entry not found")
    return entry


@router.patch("/versions/{version_id}/scope-entries/{scope_entry_id}", response_model=ScopeEntryOut)
async def update_scope_entry(
    version_id: uuid.UUID,
    scope_entry_id: uuid.UUID,
    payload: ScopeEntryUpdate,
    user: User = Depends(require_permission("version", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> ScopeEntry:
    await get_version_or_404(session, version_id, user)
    entry = await _get_scope_entry_or_404(session, version_id, scope_entry_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(entry, field, value)
    await write_audit_log(
        session,
        user=user,
        action="scope_entry.update",
        resource_type="version",
        resource_id=version_id,
        metadata={"scope_entry_id": str(scope_entry_id)},
    )
    await session.commit()
    await session.refresh(entry)
    return entry


@router.delete("/versions/{version_id}/scope-entries/{scope_entry_id}", status_code=204)
async def delete_scope_entry(
    version_id: uuid.UUID,
    scope_entry_id: uuid.UUID,
    user: User = Depends(require_permission("version", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    await get_version_or_404(session, version_id, user)
    entry = await _get_scope_entry_or_404(session, version_id, scope_entry_id)
    await write_audit_log(
        session,
        user=user,
        action="scope_entry.delete",
        resource_type="version",
        resource_id=version_id,
        metadata={"host": entry.host},
    )
    await session.delete(entry)
    await session.commit()
