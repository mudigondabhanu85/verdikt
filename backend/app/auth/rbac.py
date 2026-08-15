from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.db.session import get_db_session
from app.models.organization import User
from app.models.rbac import RolePermission


def require_permission(resource: str, action: str):
    """FastAPI dependency factory enforcing the role_permissions matrix
    (§9) — role -> permission is a DB lookup, not an if/else ladder, so
    granting a role a new permission is a data change.
    """

    async def _check(
        user: User = Depends(get_current_user),
        session: AsyncSession = Depends(get_db_session),
    ) -> User:
        result = await session.execute(
            select(RolePermission).where(
                RolePermission.role == user.role,
                RolePermission.resource == resource,
                RolePermission.action == action,
                RolePermission.allowed.is_(True),
            )
        )
        if result.scalar_one_or_none() is None:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Role '{user.role}' lacks '{action}' on '{resource}'",
            )
        return user

    return _check
