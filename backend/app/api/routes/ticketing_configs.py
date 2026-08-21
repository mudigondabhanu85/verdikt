import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.organization import User
from app.models.ticketing_config import TicketingConfig
from app.schemas.ticketing_config import TicketingConfigCreate, TicketingConfigOut
from app.vault.credential_vault import encrypt_secret, mask_secret

router = APIRouter(prefix="/ticketing-configs", tags=["ticketing-configs"])


@router.post("", response_model=TicketingConfigOut, status_code=201)
async def create_ticketing_config(
    payload: TicketingConfigCreate,
    user: User = Depends(require_permission("ticketing_config", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> TicketingConfig:
    config = TicketingConfig(
        org_id=user.org_id,
        label=payload.label,
        provider=payload.provider,
        base_url=payload.base_url,
        email=payload.email,
        encrypted_api_token=encrypt_secret(payload.api_token),
        masked_reference=mask_secret(payload.api_token),
        project_key=payload.project_key,
        issue_type=payload.issue_type,
    )
    session.add(config)
    # Audit the creation event, never the API token itself (§1.5).
    await write_audit_log(
        session,
        user=user,
        action="ticketing_config.create",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": payload.label, "provider": payload.provider, "project_key": payload.project_key},
    )
    await session.commit()
    await session.refresh(config)
    return config


@router.get("", response_model=list[TicketingConfigOut])
async def list_ticketing_configs(
    user: User = Depends(require_permission("ticketing_config", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[TicketingConfig]:
    result = await session.execute(select(TicketingConfig).where(TicketingConfig.org_id == user.org_id))
    return list(result.scalars().all())


@router.delete("/{config_id}", status_code=204)
async def delete_ticketing_config(
    config_id: uuid.UUID,
    user: User = Depends(require_permission("ticketing_config", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    config = await session.get(TicketingConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ticketing config not found")
    await write_audit_log(
        session,
        user=user,
        action="ticketing_config.delete",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": config.label},
    )
    await session.delete(config)
    await session.commit()
