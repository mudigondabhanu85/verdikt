import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.credential import CredentialSet
from app.models.login_macro import LoginMacro
from app.models.organization import User
from app.schemas.login_macro import LoginMacroOut
from app.schemas.macro_upload import MacroUploadRequest

router = APIRouter(prefix="/versions/{version_id}/credentials", tags=["credentials"])


async def _get_credential_or_404(
    session: AsyncSession, version_id: uuid.UUID, credential_id: uuid.UUID
) -> CredentialSet:
    credential = await session.get(CredentialSet, credential_id)
    if credential is None or credential.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Credential set not found")
    return credential


@router.post(
    "/{credential_id}/macros/upload", response_model=LoginMacroOut, status_code=201
)
async def upload_login_macro(
    version_id: uuid.UUID,
    credential_id: uuid.UUID,
    payload: MacroUploadRequest,
    user: User = Depends(require_permission("credential", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> LoginMacroOut:
    """Accepts a macro recorded by the standalone browser extension
    (browser-extension/) — a drop-in alternative to
    POST .../record-macro's in-app Playwright recording path. Same
    LoginMacro row shape, same replay path (app.agents.macro.MacroPlayer),
    zero backend changes needed to treat the two interchangeably.
    """
    await get_version_or_404(session, version_id, user)
    credential = await _get_credential_or_404(session, version_id, credential_id)

    macro = LoginMacro(
        version_id=version_id,
        credential_set_id=credential.id,
        steps=payload.steps,
    )
    session.add(macro)
    await write_audit_log(
        session,
        user=user,
        action="credential.upload_macro",
        resource_type="version",
        resource_id=version_id,
        metadata={"credential_id": str(credential.id), "step_count": len(payload.steps)},
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
