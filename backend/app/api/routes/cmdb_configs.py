import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.integrations.cmdb.client import CMDBClient, CMDBLookupError
from app.models.cmdb_config import CMDBConfig
from app.models.organization import User
from app.schemas.cmdb_config import (
    AssetMetadataOut,
    CMDBAssetLookupRequest,
    CMDBConfigCreate,
    CMDBConfigOut,
)
from app.vault.credential_vault import decrypt_secret, encrypt_secret, mask_secret

router = APIRouter(prefix="/cmdb-configs", tags=["cmdb-configs"])


@router.post("", response_model=CMDBConfigOut, status_code=201)
async def create_cmdb_config(
    payload: CMDBConfigCreate,
    user: User = Depends(require_permission("cmdb_config", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> CMDBConfig:
    config = CMDBConfig(
        org_id=user.org_id,
        label=payload.label,
        provider=payload.provider,
        lookup_url_template=payload.lookup_url_template,
        auth_header_name=payload.auth_header_name,
        encrypted_auth_header_value=encrypt_secret(payload.auth_header_value),
        masked_reference=mask_secret(payload.auth_header_value),
        owner_json_path=payload.owner_json_path,
        criticality_json_path=payload.criticality_json_path,
    )
    session.add(config)
    # Audit the creation event, never the auth header value itself (§1.5)
    # — it's a bearer secret, same as an API key.
    await write_audit_log(
        session,
        user=user,
        action="cmdb_config.create",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": payload.label, "provider": payload.provider},
    )
    await session.commit()
    await session.refresh(config)
    return config


@router.get("", response_model=list[CMDBConfigOut])
async def list_cmdb_configs(
    user: User = Depends(require_permission("cmdb_config", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[CMDBConfig]:
    result = await session.execute(select(CMDBConfig).where(CMDBConfig.org_id == user.org_id))
    return list(result.scalars().all())


@router.delete("/{config_id}", status_code=204)
async def delete_cmdb_config(
    config_id: uuid.UUID,
    user: User = Depends(require_permission("cmdb_config", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    config = await session.get(CMDBConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CMDB config not found")
    await write_audit_log(
        session,
        user=user,
        action="cmdb_config.delete",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"label": config.label},
    )
    await session.delete(config)
    await session.commit()


@router.post("/{config_id}/lookup", response_model=AssetMetadataOut)
async def lookup_cmdb_asset(
    config_id: uuid.UUID,
    payload: CMDBAssetLookupRequest,
    user: User = Depends(require_permission("cmdb_config", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> AssetMetadataOut:
    """A real, live lookup against the configured CMDB right now — doubles
    as both the day-to-day asset-metadata lookup and the "does this
    connection actually work" check an analyst runs after configuring it
    (no local caching, same as Jira/Slack never caching external state)."""
    config = await session.get(CMDBConfig, config_id)
    if config is None or config.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CMDB config not found")

    auth_header_value = decrypt_secret(config.encrypted_auth_header_value)
    client = CMDBClient(
        config.lookup_url_template,
        config.auth_header_name,
        auth_header_value,
        config.owner_json_path,
        config.criticality_json_path,
    )
    try:
        asset = await client.get_asset(payload.identifier)
    except CMDBLookupError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    return AssetMetadataOut(
        identifier=asset.identifier, owner=asset.owner, criticality=asset.criticality, raw=asset.raw
    )
