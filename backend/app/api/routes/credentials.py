import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.macro import MacroRecorder
from app.api.deps import get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.credential import CredentialSet
from app.models.login_macro import LoginMacro
from app.models.organization import User
from app.schemas.credential import CredentialSetCreate, CredentialSetOut
from app.schemas.login_macro import LoginMacroOut, RecordMacroRequest
from app.vault.credential_vault import encrypt_credential, mask_reference

router = APIRouter(prefix="/versions/{version_id}/credentials", tags=["credentials"])


async def _get_credential_or_404(
    session: AsyncSession, version_id: uuid.UUID, credential_id: uuid.UUID
) -> CredentialSet:
    credential = await session.get(CredentialSet, credential_id)
    if credential is None or credential.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Credential set not found")
    return credential


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
    credential = await _get_credential_or_404(session, version_id, credential_id)
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


@router.post("/{credential_id}/record-macro", response_model=LoginMacroOut, status_code=201)
async def record_login_macro(
    version_id: uuid.UUID,
    credential_id: uuid.UUID,
    payload: RecordMacroRequest,
    user: User = Depends(require_permission("credential", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> LoginMacroOut:
    """Launches a local headed browser and blocks until the analyst
    finishes logging in (including any manual OTP step) and closes it,
    then stores the recorded action sequence as a LoginMacro tied to this
    CredentialSet (§4/§5). Deliberately simple/synchronous for this MVP
    rather than a full async-job+notification flow — only usable when the
    API server has a local display to open a browser window on, which is
    fine for the self-hosted single-analyst deployment this targets;
    a later pass can move this to a background job with a status-poll
    endpoint for remote/headless deployments.
    """
    await get_version_or_404(session, version_id, user.org_id)
    credential = await _get_credential_or_404(session, version_id, credential_id)

    recorder = MacroRecorder()
    steps = await recorder.record(payload.start_url, headless=False)

    macro = LoginMacro(
        version_id=version_id,
        credential_set_id=credential.id,
        steps=[step.to_dict() for step in steps],
    )
    session.add(macro)
    await write_audit_log(
        session,
        user=user,
        action="credential.record_macro",
        resource_type="version",
        resource_id=version_id,
        metadata={"credential_id": str(credential.id), "step_count": len(steps)},
    )
    await session.commit()
    await session.refresh(macro)

    return LoginMacroOut(
        id=macro.id,
        version_id=macro.version_id,
        credential_set_id=macro.credential_set_id,
        step_count=len(macro.steps),
        created_at=macro.created_at,
    )


@router.get("/{credential_id}/macros", response_model=list[LoginMacroOut])
async def list_login_macros(
    version_id: uuid.UUID,
    credential_id: uuid.UUID,
    user: User = Depends(require_permission("credential", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[LoginMacroOut]:
    """§7 frontend — lets the UI show whether a credential already has a
    recorded macro (and how many steps) without re-deriving that from
    record_login_macro's one-shot response, which nothing previously
    persisted client-side."""
    await get_version_or_404(session, version_id, user.org_id)
    await _get_credential_or_404(session, version_id, credential_id)
    result = await session.execute(
        select(LoginMacro).where(LoginMacro.credential_set_id == credential_id)
    )
    return [
        LoginMacroOut(
            id=macro.id,
            version_id=macro.version_id,
            credential_set_id=macro.credential_set_id,
            step_count=len(macro.steps),
            created_at=macro.created_at,
        )
        for macro in result.scalars().all()
    ]
