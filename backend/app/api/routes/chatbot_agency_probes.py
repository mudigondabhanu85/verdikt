import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.chatbot_agency_probe import ChatbotAgencyProbe
from app.models.chatbot_target import ChatbotTarget
from app.models.organization import User
from app.schemas.chatbot_agency_probe import ChatbotAgencyProbeCreate, ChatbotAgencyProbeOut

router = APIRouter(
    prefix="/versions/{version_id}/chatbot-targets/{target_id}/agency-probes", tags=["chatbot-agency-probes"]
)


async def _get_target_or_404(session: AsyncSession, version_id: uuid.UUID, target_id: uuid.UUID) -> ChatbotTarget:
    target = await session.get(ChatbotTarget, target_id)
    if target is None or target.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Chatbot target not found")
    return target


@router.post("", response_model=ChatbotAgencyProbeOut, status_code=201)
async def create_chatbot_agency_probe(
    version_id: uuid.UUID,
    target_id: uuid.UUID,
    payload: ChatbotAgencyProbeCreate,
    user: User = Depends(require_permission("chatbot_target", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> ChatbotAgencyProbe:
    await get_version_or_404(session, version_id, user.org_id)
    await _get_target_or_404(session, version_id, target_id)
    probe = ChatbotAgencyProbe(
        chatbot_target_id=target_id,
        forbidden_action=payload.forbidden_action,
        created_by=user.id,
    )
    session.add(probe)
    await write_audit_log(
        session,
        user=user,
        action="chatbot_agency_probe.create",
        resource_type="version",
        resource_id=version_id,
        metadata={"target_id": str(target_id), "forbidden_action": payload.forbidden_action},
    )
    await session.commit()
    await session.refresh(probe)
    return probe


@router.get("", response_model=list[ChatbotAgencyProbeOut])
async def list_chatbot_agency_probes(
    version_id: uuid.UUID,
    target_id: uuid.UUID,
    user: User = Depends(require_permission("chatbot_target", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[ChatbotAgencyProbe]:
    await get_version_or_404(session, version_id, user.org_id)
    await _get_target_or_404(session, version_id, target_id)
    result = await session.execute(
        select(ChatbotAgencyProbe).where(ChatbotAgencyProbe.chatbot_target_id == target_id)
    )
    return list(result.scalars().all())


@router.delete("/{probe_id}", status_code=204)
async def delete_chatbot_agency_probe(
    version_id: uuid.UUID,
    target_id: uuid.UUID,
    probe_id: uuid.UUID,
    user: User = Depends(require_permission("chatbot_target", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    await get_version_or_404(session, version_id, user.org_id)
    await _get_target_or_404(session, version_id, target_id)
    probe = await session.get(ChatbotAgencyProbe, probe_id)
    if probe is None or probe.chatbot_target_id != target_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agency probe not found")
    await write_audit_log(
        session,
        user=user,
        action="chatbot_agency_probe.delete",
        resource_type="version",
        resource_id=version_id,
        metadata={"target_id": str(target_id), "forbidden_action": probe.forbidden_action},
    )
    await session.delete(probe)
    await session.commit()
