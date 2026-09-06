import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.integrations.vgs.client import VGSClient, VGSPushError
from app.models.organization import User
from app.models.vgs_config import VGSConfig
from app.schemas.vgs_config import VGSConfigCreate, VGSConfigOut
from app.vault.credential_vault import decrypt_secret, encrypt_secret, mask_secret

router = APIRouter(prefix="/vgs-configs", tags=["vgs-configs"])


@router.post("", response_model=VGSConfigOut, status_code=201)
async def create_vgs_config(
    payload: VGSConfigCreate,
    user: User = Depends(require_permission("vgs_config", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> VGSConfig:
    config = VGSConfig(
        org_id=user.org_id,
        label=payload.label,
        encrypted_webhook_url=encrypt_secret(payload.webhook_url),
        masked_reference=mask_secret(payload.webhook_url),
        push_on_scan_completed=payload.push_on_scan_completed,
        auth_type=payload.auth_type,
        encrypted_auth_value=encrypt_secret(payload.auth_value) if payload.auth_value else None,
        masked_auth_reference=mask_secret(payload.auth_value) if payload.auth_value else None,
    )
    session.add(config)
    # Audit the creation event, never the webhook URL itself (§1.5) — it's
    # a bearer secret, same as an API key.
    await write_audit_log(
        session,
        user=user,
        action="vgs_config.create",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": payload.label},
    )
    await session.commit()
    await session.refresh(config)
    return config


@router.get("", response_model=list[VGSConfigOut])
async def list_vgs_configs(
    user: User = Depends(require_permission("vgs_config", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[VGSConfig]:
    result = await session.execute(select(VGSConfig).where(VGSConfig.org_id == user.org_id))
    return list(result.scalars().all())


@router.delete("/{config_id}", status_code=204)
async def delete_vgs_config(
    config_id: uuid.UUID,
    user: User = Depends(require_permission("vgs_config", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    config = await session.get(VGSConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VGS config not found")
    await write_audit_log(
        session,
        user=user,
        action="vgs_config.delete",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": config.label},
    )
    await session.delete(config)
    await session.commit()


@router.post("/{config_id}/test", status_code=204)
async def test_vgs_config(
    config_id: uuid.UUID,
    user: User = Depends(require_permission("vgs_config", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    """Pushes a real, empty-findings test payload through the configured
    webhook right now — lets an analyst confirm the URL actually works
    before relying on it to fire silently in the background when a scan
    completes."""
    config = await session.get(VGSConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VGS config not found")

    webhook_url = decrypt_secret(config.encrypted_webhook_url)
    auth_value = decrypt_secret(config.encrypted_auth_value) if config.encrypted_auth_value else None
    client = VGSClient(webhook_url, auth_type=config.auth_type, auth_value=auth_value)
    try:
        await client.push_findings("test", [])
    except VGSPushError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
