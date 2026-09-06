import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_project_or_404, get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.credential import CredentialSet
from app.models.organization import User
from app.models.project import AuthorizationRecord, ScopeEntry, Version
from app.schemas.version import (
    AuthorizationRecordOut,
    ScopeEntryCreate,
    ScopeEntryOut,
    VersionCreate,
    VersionOut,
)
from app.storage.local_disk import get_object_storage

router = APIRouter(tags=["versions"])


@router.post("/projects/{project_id}/versions", response_model=VersionOut, status_code=201)
async def create_version(
    project_id: uuid.UUID,
    payload: VersionCreate,
    user: User = Depends(require_permission("version", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> Version:
    await get_project_or_404(session, project_id, user.org_id)
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
    await session.refresh(version, attribute_names=["authorization_records"])
    return version


@router.get("/projects/{project_id}/versions", response_model=list[VersionOut])
async def list_versions(
    project_id: uuid.UUID,
    user: User = Depends(require_permission("version", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[Version]:
    await get_project_or_404(session, project_id, user.org_id)
    result = await session.execute(
        select(Version)
        .where(Version.project_id == project_id)
        .order_by(Version.created_at)
    )
    versions = list(result.scalars().unique().all())
    for v in versions:
        await session.refresh(v, attribute_names=["authorization_records"])
    return versions


@router.get("/versions/{version_id}", response_model=VersionOut)
async def get_version(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("version", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> Version:
    version = await get_version_or_404(session, version_id, user.org_id)
    await session.refresh(version, attribute_names=["authorization_records"])
    return version


@router.post(
    "/versions/{version_id}/scope-entries", response_model=ScopeEntryOut, status_code=201
)
async def add_scope_entry(
    version_id: uuid.UUID,
    payload: ScopeEntryCreate,
    user: User = Depends(require_permission("version", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> ScopeEntry:
    await get_version_or_404(session, version_id, user.org_id)
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
    await get_version_or_404(session, version_id, user.org_id)
    result = await session.execute(select(ScopeEntry).where(ScopeEntry.version_id == version_id))
    return list(result.scalars().all())


@router.post(
    "/versions/{version_id}/authorization",
    response_model=AuthorizationRecordOut,
    status_code=201,
)
async def add_authorization_record(
    version_id: uuid.UUID,
    approver_name: str = Form(...),
    attestation_text: str | None = Form(None),
    letter: UploadFile | None = File(None),
    user: User = Depends(require_permission("version", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> AuthorizationRecord:
    """Records the §1 authorization gate for this Version — approver name
    plus either a checkbox-style attestation or an uploaded authorization
    letter (or both). A Version's is_authorized flag flips true as soon as
    at least one of these exists."""
    await get_version_or_404(session, version_id, user.org_id)

    letter_object_key = None
    if letter is not None:
        letter_object_key = f"versions/{version_id}/authorization/{letter.filename}"
        await get_object_storage().put(letter_object_key, await letter.read())

    record = AuthorizationRecord(
        version_id=version_id,
        approver_name=approver_name,
        attestation_text=attestation_text,
        letter_object_key=letter_object_key,
        attested_by=user.id,
        attested_at=datetime.now(timezone.utc),
    )
    session.add(record)
    await write_audit_log(
        session,
        user=user,
        action="authorization.grant",
        resource_type="version",
        resource_id=version_id,
        metadata={"approver_name": approver_name, "letter_uploaded": letter_object_key is not None},
    )
    await session.commit()
    await session.refresh(record)
    return record


@router.get(
    "/versions/{version_id}/authorization", response_model=list[AuthorizationRecordOut]
)
async def list_authorization_records(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("version", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[AuthorizationRecord]:
    await get_version_or_404(session, version_id, user.org_id)
    result = await session.execute(
        select(AuthorizationRecord).where(AuthorizationRecord.version_id == version_id)
    )
    return list(result.scalars().all())
