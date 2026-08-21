import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.ai_provider_config import AIProviderConfig
from app.models.organization import User
from app.schemas.ai_provider_config import AIProviderConfigCreate, AIProviderConfigOut
from app.vault.credential_vault import encrypt_secret, mask_secret

router = APIRouter(prefix="/ai-provider-configs", tags=["ai-provider-configs"])


@router.post("", response_model=AIProviderConfigOut, status_code=201)
async def create_ai_provider_config(
    payload: AIProviderConfigCreate,
    user: User = Depends(require_permission("ai_provider_config", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> AIProviderConfig:
    config = AIProviderConfig(
        org_id=user.org_id,
        label=payload.label,
        provider=payload.provider,
        model=payload.model,
        base_url=payload.base_url,
        encrypted_api_key=encrypt_secret(payload.api_key),
        masked_reference=mask_secret(payload.api_key),
    )
    session.add(config)
    # Audit the creation event, never the API key itself (§1.5).
    await write_audit_log(
        session,
        user=user,
        action="ai_provider_config.create",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": payload.label, "provider": payload.provider, "model": payload.model},
    )
    await session.commit()
    await session.refresh(config)
    return config


@router.get("", response_model=list[AIProviderConfigOut])
async def list_ai_provider_configs(
    user: User = Depends(require_permission("ai_provider_config", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[AIProviderConfig]:
    result = await session.execute(
        select(AIProviderConfig).where(AIProviderConfig.org_id == user.org_id)
    )
    return list(result.scalars().all())


@router.delete("/{config_id}", status_code=204)
async def delete_ai_provider_config(
    config_id: uuid.UUID,
    user: User = Depends(require_permission("ai_provider_config", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    config = await session.get(AIProviderConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "AI provider config not found")
    await write_audit_log(
        session,
        user=user,
        action="ai_provider_config.delete",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": config.label},
    )
    await session.delete(config)
    await session.commit()
