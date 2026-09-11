import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.ai_provider_config import AIProviderConfig
from app.models.organization import User
from app.schemas.ai_provider_config import (
    AIProviderConfigCreate,
    AIProviderConfigOut,
    AIProviderConfigRotateSecret,
    AIProviderConfigUpdateModels,
)
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
        model_reasoning=payload.model_reasoning,
        model_classification=payload.model_classification,
        base_url=payload.base_url,
        auth_type=payload.auth_type,
        encrypted_api_key=encrypt_secret(payload.api_key),
        masked_reference=mask_secret(payload.api_key),
        secret_rotated_at=datetime.now(timezone.utc),
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


@router.post("/{config_id}/rotate-secret", response_model=AIProviderConfigOut)
async def rotate_ai_provider_config_secret(
    config_id: uuid.UUID,
    payload: AIProviderConfigRotateSecret,
    user: User = Depends(require_permission("ai_provider_config", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> AIProviderConfig:
    """Updates just the secret on an existing row — label, provider,
    model, base_url, and (crucially) is_default all stay unchanged.
    Covers the routine "my token expired, here's a new one" action
    without a delete-and-recreate or re-picking "set default".
    """
    config = await session.get(AIProviderConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "AI provider config not found")

    updated_fields = []
    if payload.api_key is not None:
        config.encrypted_api_key = encrypt_secret(payload.api_key)
        config.masked_reference = mask_secret(payload.api_key)
        config.secret_rotated_at = datetime.now(timezone.utc)
        updated_fields.append("api_key")

    if updated_fields:
        # Never log the secret itself — just which field(s) changed (§1.5).
        await write_audit_log(
            session,
            user=user,
            action="ai_provider_config.rotate_secret",
            resource_type="organization",
            resource_id=user.org_id,
            metadata={"label": config.label, "fields_rotated": updated_fields},
        )
        await session.commit()
        await session.refresh(config)
    return config


@router.patch("/{config_id}/models", response_model=AIProviderConfigOut)
async def update_ai_provider_config_models(
    config_id: uuid.UUID,
    payload: AIProviderConfigUpdateModels,
    user: User = Depends(require_permission("ai_provider_config", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> AIProviderConfig:
    """Routes different agent roles to different models on the same
    provider account (see app.ai.model_routing.ModelRouter) — separate
    from rotate-secret (which never touches model fields) and from
    set-default. An empty string clears a tier override back to
    following `model`; omitting a field leaves it untouched.
    """
    config = await session.get(AIProviderConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "AI provider config not found")

    updated_fields = []
    if payload.model is not None and payload.model:
        config.model = payload.model
        updated_fields.append("model")
    if payload.model_reasoning is not None:
        config.model_reasoning = payload.model_reasoning or None
        updated_fields.append("model_reasoning")
    if payload.model_classification is not None:
        config.model_classification = payload.model_classification or None
        updated_fields.append("model_classification")

    if updated_fields:
        await write_audit_log(
            session,
            user=user,
            action="ai_provider_config.update_models",
            resource_type="organization",
            resource_id=user.org_id,
            metadata={"label": config.label, "fields_updated": updated_fields},
        )
        await session.commit()
        await session.refresh(config)
    return config


@router.post("/{config_id}/set-default", response_model=AIProviderConfigOut)
async def set_default_ai_provider_config(
    config_id: uuid.UUID,
    user: User = Depends(require_permission("ai_provider_config", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> AIProviderConfig:
    """Makes this the org's default provider — used by every scan that
    doesn't specify its own AIProviderConfig (see
    app.ai.provider.resolve_provider_and_model). The whole point: an org
    configures its own LLM (Claude, OpenAI, or any in-house
    OpenAI-compatible gateway) once, here, with no .env editing needed.
    Unsets whichever config was previously default first — the partial
    unique index (migration 0023) only allows one is_default=True row
    per org, so setting the new one before clearing the old one would
    violate it.
    """
    config = await session.get(AIProviderConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "AI provider config not found")

    await session.execute(
        update(AIProviderConfig)
        .where(AIProviderConfig.org_id == user.org_id, AIProviderConfig.id != config_id)
        .values(is_default=False)
    )
    config.is_default = True
    await write_audit_log(
        session,
        user=user,
        action="ai_provider_config.set_default",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": config.label},
    )
    await session.commit()
    await session.refresh(config)
    return config


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
