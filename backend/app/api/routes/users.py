import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import write_audit_log
from app.auth.rbac import require_permission
from app.auth.security import create_access_token, hash_password
from app.db.session import get_db_session
from app.models.organization import BASELINE_ROLES, User
from app.schemas.auth import TokenResponse
from app.schemas.user import AcceptInviteRequest, UserInviteCreate, UserInviteOut, UserOut

router = APIRouter(prefix="/users", tags=["users"])


@router.post("/invite", response_model=UserInviteOut, status_code=201)
async def invite_user(
    payload: UserInviteCreate,
    user: User = Depends(require_permission("user", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> User:
    if payload.role not in BASELINE_ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown role: {payload.role!r}")

    existing = await session.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    invitee = User(
        org_id=user.org_id,
        email=payload.email,
        hashed_password=None,
        role=payload.role,
        is_active=True,
        invite_token=secrets.token_urlsafe(32),
        invited_at=datetime.now(timezone.utc),
    )
    session.add(invitee)
    await write_audit_log(
        session,
        user=user,
        action="user.invite",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"email": payload.email, "role": payload.role},
    )
    await session.commit()
    await session.refresh(invitee)
    return invitee


@router.get("", response_model=list[UserOut])
async def list_users(
    user: User = Depends(require_permission("user", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[User]:
    result = await session.execute(select(User).where(User.org_id == user.org_id))
    return list(result.scalars().all())


@router.post("/accept-invite", response_model=TokenResponse)
async def accept_invite(
    payload: AcceptInviteRequest, session: AsyncSession = Depends(get_db_session)
) -> TokenResponse:
    result = await session.execute(select(User).where(User.invite_token == payload.invite_token))
    invitee = result.scalar_one_or_none()
    if invitee is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Invalid or already-used invite token")

    invitee.hashed_password = hash_password(payload.password)
    invitee.invite_token = None
    invitee.invite_accepted_at = datetime.now(timezone.utc)
    await session.commit()

    return TokenResponse(access_token=create_access_token(invitee.id))


@router.post("/{user_id}/deactivate", status_code=204)
async def deactivate_user(
    user_id: uuid.UUID,
    user: User = Depends(require_permission("user", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    target = await session.get(User, user_id)
    if target is None or target.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    if target.role == "org_admin" and target.is_active:
        other_active_admins = await session.execute(
            select(func.count())
            .select_from(User)
            .where(
                User.org_id == user.org_id,
                User.role == "org_admin",
                User.is_active.is_(True),
                User.id != target.id,
            )
        )
        if other_active_admins.scalar_one() == 0:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Cannot deactivate the last active org_admin in the organization",
            )

    target.is_active = False
    await write_audit_log(
        session,
        user=user,
        action="user.deactivate",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"target_user_id": str(target.id), "email": target.email},
    )
    await session.commit()


@router.post("/{user_id}/reactivate", status_code=204)
async def reactivate_user(
    user_id: uuid.UUID,
    user: User = Depends(require_permission("user", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    target = await session.get(User, user_id)
    if target is None or target.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    target.is_active = True
    await write_audit_log(
        session,
        user=user,
        action="user.reactivate",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"target_user_id": str(target.id), "email": target.email},
    )
    await session.commit()
