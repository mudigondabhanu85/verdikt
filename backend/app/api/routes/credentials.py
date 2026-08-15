import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.credential import CredentialSet
from app.models.organization import User
from app.schemas.credential import CredentialSetCreate, CredentialSetOut
from app.vault.credential_vault import encrypt_credential, mask_reference

router = APIRouter(prefix="/versions/{version_id}/credentials", tags=["credentials"])


@router.post("", response_model=CredentialSetOut, status_code=201)
async def add_credential_set(
    version_id: uuid.UUID,
    payload: CredentialSetCreate,
    user: User = Depends(require_permission("credential", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> CredentialSet:
    await get_version_or_404(session, version_id, user.org_id)
    credential = CredentialSet(
        version_id=version_id,
        label=payload.label,
        credential_type=payload.credential_type,
        encrypted_secret=encrypt_credential(payload.username, payload.secret),
        masked_reference=mask_reference(payload.username, payload.secret),
        login_endpoint=payload.login_endpoint,
        login_method=payload.login_method,
        login_body_template=payload.login_body_template,
        login_content_type=payload.login_content_type,
        token_response_path=payload.token_response_path,
    )
    session.add(credential)
    # Audit the creation event, never the secret material itself (§1.5).
    await write_audit_log(
        session,
        user=user,
        action="credential.create",
        resource_type="version",
        resource_id=version_id,
        metadata={"label": payload.label, "credential_type": payload.credential_type},
    )
    await session.commit()
    await session.refresh(credential)
    return credential


@router.get("", response_model=list[CredentialSetOut])
async def list_credential_sets(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("credential", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[CredentialSet]:
    await get_version_or_404(session, version_id, user.org_id)
    result = await session.execute(
        select(CredentialSet).where(CredentialSet.version_id == version_id)
    )
    return list(result.scalars().all())


@router.delete("/{credential_id}", status_code=204)
async def delete_credential_set(
    version_id: uuid.UUID,
    credential_id: uuid.UUID,
    user: User = Depends(require_permission("credential", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    await get_version_or_404(session, version_id, user.org_id)
    credential = await session.get(CredentialSet, credential_id)
    if credential is None or credential.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Credential set not found")
    await write_audit_log(
        session,
        user=user,
        action="credential.delete",
        resource_type="version",
        resource_id=version_id,
        metadata={"label": credential.label},
    )
    await session.delete(credential)
    await session.commit()
