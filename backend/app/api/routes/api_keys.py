import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import write_audit_log
from app.auth.dependencies import get_current_user
from app.auth.security import generate_api_key
from app.db.session import get_db_session
from app.models.api_key import ApiKey
from app.models.organization import User
from app.schemas.api_key import ApiKeyCreate, ApiKeyCreated, ApiKeyOut

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: ApiKeyCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ApiKeyCreated:
    """Self-service, not RBAC-gated — any authenticated user can create a
    key for themselves (§9). The key authenticates as this exact user
    (same org/role/permissions they already have), so no new permission
    axis is needed for this endpoint itself.
    """
    raw_key, key_prefix, hashed_key = generate_api_key()
    api_key = ApiKey(
        org_id=user.org_id,
        user_id=user.id,
        label=payload.label,
        key_prefix=key_prefix,
        hashed_key=hashed_key,
    )
    session.add(api_key)
    await write_audit_log(
        session,
        user=user,
        action="api_key.create",
        resource_type="user",
        resource_id=user.id,
        metadata={"label": payload.label, "key_prefix": key_prefix},
    )
    await session.commit()
    await session.refresh(api_key)

    return ApiKeyCreated(id=api_key.id, label=api_key.label, api_key=raw_key, key_prefix=key_prefix)


@router.get("", response_model=list[ApiKeyOut])
async def list_my_api_keys(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> list[ApiKey]:
    """Lists only the caller's own keys — API keys are a personal
    credential, not an org-wide resource an analyst/viewer should be
    able to browse.
    """
    result = await session.execute(select(ApiKey).where(ApiKey.user_id == user.id))
    return list(result.scalars().all())


@router.post("/{api_key_id}/revoke", response_model=ApiKeyOut)
async def revoke_api_key(
    api_key_id: uuid.UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ApiKey:
    """A user can revoke their own key; an org_admin can revoke any key
    within their org (e.g. an offboarding teammate's key)."""
    api_key = await session.get(ApiKey, api_key_id)
    if api_key is None or api_key.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    if api_key.user_id != user.id and user.role != "org_admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot revoke another user's API key")

    if api_key.revoked_at is None:
        api_key.revoked_at = datetime.now(timezone.utc)
        await write_audit_log(
            session,
            user=user,
            action="api_key.revoke",
            resource_type="user",
            resource_id=api_key.user_id,
            metadata={"label": api_key.label, "key_prefix": api_key.key_prefix},
        )
        await session.commit()
        await session.refresh(api_key)
    return api_key
