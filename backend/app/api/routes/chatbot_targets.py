import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.chatbot_target import ChatbotTarget
from app.models.organization import User
from app.schemas.chatbot_target import ChatbotTargetCreate, ChatbotTargetOut
from app.vault.credential_vault import encrypt_secret, mask_secret

router = APIRouter(prefix="/versions/{version_id}/chatbot-targets", tags=["chatbot-targets"])


@router.post("", response_model=ChatbotTargetOut, status_code=201)
async def create_chatbot_target(
    version_id: uuid.UUID,
    payload: ChatbotTargetCreate,
    user: User = Depends(require_permission("chatbot_target", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> ChatbotTarget:
    await get_version_or_404(session, version_id, user)
    target = ChatbotTarget(
        version_id=version_id,
        label=payload.label,
        endpoint_url=payload.endpoint_url,
        http_method=payload.http_method,
        request_body_template=payload.request_body_template,
        content_type=payload.content_type,
        response_text_path=payload.response_text_path,
        auth_header_name=payload.auth_header_name if payload.auth_header_value else None,
        encrypted_auth_header_value=(
            encrypt_secret(payload.auth_header_value) if payload.auth_header_value else None
        ),
        masked_reference=mask_secret(payload.auth_header_value) if payload.auth_header_value else None,
        created_by=user.id,
    )
    session.add(target)
    # Audit the creation event, never the auth header value itself (§1.5)
    # — it's a bearer secret, same as every other integration's.
    await write_audit_log(
        session,
        user=user,
        action="chatbot_target.create",
        resource_type="version",
        resource_id=version_id,
        metadata={"label": payload.label, "endpoint_url": payload.endpoint_url},
    )
    await session.commit()
    await session.refresh(target)
    return target


@router.get("", response_model=list[ChatbotTargetOut])
async def list_chatbot_targets(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("chatbot_target", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[ChatbotTarget]:
    await get_version_or_404(session, version_id, user)
    result = await session.execute(select(ChatbotTarget).where(ChatbotTarget.version_id == version_id))
    return list(result.scalars().all())


@router.delete("/{target_id}", status_code=204)
async def delete_chatbot_target(
    version_id: uuid.UUID,
    target_id: uuid.UUID,
    user: User = Depends(require_permission("chatbot_target", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    await get_version_or_404(session, version_id, user)
    target = await session.get(ChatbotTarget, target_id)
    if target is None or target.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Chatbot target not found")
    await write_audit_log(
        session,
        user=user,
        action="chatbot_target.delete",
        resource_type="version",
        resource_id=version_id,
        metadata={"label": target.label},
    )
    await session.delete(target)
    await session.commit()
