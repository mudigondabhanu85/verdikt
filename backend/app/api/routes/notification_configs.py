import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.notification_config import NotificationConfig
from app.models.organization import User
from app.notifications.dispatch import NotificationDispatchError, send_notification
from app.schemas.notification_config import NotificationConfigCreate, NotificationConfigOut
from app.vault.credential_vault import encrypt_secret, mask_secret

router = APIRouter(prefix="/notification-configs", tags=["notification-configs"])


@router.post("", response_model=NotificationConfigOut, status_code=201)
async def create_notification_config(
    payload: NotificationConfigCreate,
    user: User = Depends(require_permission("notification_config", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> NotificationConfig:
    if payload.provider == "outlook":
        smtp_config = {
            "smtp_host": payload.smtp_host,
            "smtp_port": payload.smtp_port,
            "smtp_username": payload.smtp_username,
            "smtp_password": payload.smtp_password,
            "from_address": payload.from_address,
            "to_address": payload.to_address,
        }
        config = NotificationConfig(
            org_id=user.org_id,
            label=payload.label,
            provider=payload.provider,
            encrypted_config_json=encrypt_secret(json.dumps(smtp_config)),
            masked_reference=f"{payload.smtp_host}:{payload.smtp_port} -> {payload.to_address}",
            notify_on_scan_completed=payload.notify_on_scan_completed,
        )
    else:
        config = NotificationConfig(
            org_id=user.org_id,
            label=payload.label,
            provider=payload.provider,
            encrypted_webhook_url=encrypt_secret(payload.webhook_url),
            masked_reference=mask_secret(payload.webhook_url),
            notify_on_scan_completed=payload.notify_on_scan_completed,
        )
    session.add(config)
    # Audit the creation event, never the webhook URL itself (§1.5) — it's
    # a bearer secret, same as an API key.
    await write_audit_log(
        session,
        user=user,
        action="notification_config.create",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": payload.label, "provider": payload.provider},
    )
    await session.commit()
    await session.refresh(config)
    return config


@router.get("", response_model=list[NotificationConfigOut])
async def list_notification_configs(
    user: User = Depends(require_permission("notification_config", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[NotificationConfig]:
    result = await session.execute(select(NotificationConfig).where(NotificationConfig.org_id == user.org_id))
    return list(result.scalars().all())


@router.delete("/{config_id}", status_code=204)
async def delete_notification_config(
    config_id: uuid.UUID,
    user: User = Depends(require_permission("notification_config", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    config = await session.get(NotificationConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Notification config not found")
    await write_audit_log(
        session,
        user=user,
        action="notification_config.delete",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": config.label},
    )
    await session.delete(config)
    await session.commit()


@router.post("/{config_id}/test", status_code=204)
async def test_notification_config(
    config_id: uuid.UUID,
    user: User = Depends(require_permission("notification_config", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    """Sends a real message through the configured webhook right now —
    lets an analyst confirm the URL actually works before relying on it
    to fire silently in the background when a scan completes."""
    config = await session.get(NotificationConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Notification config not found")

    try:
        await send_notification(
            config, f'Verdikt test notification from "{config.label}" — this connection works.'
        )
    except NotificationDispatchError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
