import uuid
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.security import decode_access_token, hash_api_key
from app.db.session import get_db_session
from app.models.api_key import API_KEY_PREFIX, ApiKey
from app.models.organization import User

_bearer = HTTPBearer(auto_error=False)


async def _resolve_api_key_user(raw_key: str, session: AsyncSession) -> User:
    result = await session.execute(
        select(ApiKey).where(ApiKey.hashed_key == hash_api_key(raw_key))
    )
    api_key = result.scalar_one_or_none()
    if api_key is None or api_key.revoked_at is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or revoked API key")

    user = await session.get(User, api_key.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")

    api_key.last_used_at = datetime.now(timezone.utc)
    await session.commit()
    return user


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: AsyncSession = Depends(get_db_session),
) -> User:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")

    # Two credential shapes share this one Authorization: Bearer header —
    # a short-lived JWT from interactive login, or a long-lived API key
    # (§9) for programmatic access. The vdk_ prefix disambiguates them.
    if credentials.credentials.startswith(API_KEY_PREFIX):
        return await _resolve_api_key_user(credentials.credentials, session)

    try:
        user_id: uuid.UUID = decode_access_token(credentials.credentials)
    except Exception as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token") from exc

    user = await session.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
    return user
