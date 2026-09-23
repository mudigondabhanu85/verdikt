import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import write_audit_log
from app.auth.rbac import require_permission
from app.auth.security import create_access_token, hash_password
from app.db.session import get_db_session
from app.models.organization import BASELINE_ROLES, User
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.schemas.auth import TokenResponse
from app.schemas.user import (
    AcceptInviteRequest,
    UserInviteCreate,
    UserInviteOut,
    UserOut,
    UserProjectMembershipsUpdate,
    UserRoleUpdate,
)

router = APIRouter(prefix="/users", tags=["users"])


async def _project_ids_by_user(session: AsyncSession, user_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[uuid.UUID]]:
    if not user_ids:
        return {}
    rows = await session.execute(
        select(ProjectMembership.user_id, ProjectMembership.project_id).where(
            ProjectMembership.user_id.in_(user_ids)
        )
    )
    by_user: dict[uuid.UUID, list[uuid.UUID]] = {uid: [] for uid in user_ids}
    for user_id, project_id in rows:
        by_user[user_id].append(project_id)
    return by_user


async def _other_active_admins_count(session: AsyncSession, *, org_id: uuid.UUID, excluding: uuid.UUID) -> int:
    result = await session.execute(
        select(func.count())
        .select_from(User)
        .where(
            User.org_id == org_id,
            User.role == "org_admin",
            User.is_active.is_(True),
            User.id != excluding,
        )
    )
    return result.scalar_one()


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

    # Setting a password directly skips the invite-link handoff entirely
    # — the account is created active, with no invite_token to send
    # anywhere. Omitting it keeps the original behavior unchanged: a
    # token the invitee exchanges for their own, self-chosen password.
    invitee = User(
        org_id=user.org_id,
        email=payload.email,
        hashed_password=hash_password(payload.password) if payload.password else None,
        role=payload.role,
        is_active=True,
        invite_token=None if payload.password else secrets.token_urlsafe(32),
        invited_at=datetime.now(timezone.utc),
        invite_accepted_at=datetime.now(timezone.utc) if payload.password else None,
    )
    session.add(invitee)
    await write_audit_log(
        session,
        user=user,
        action="user.invite",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"email": payload.email, "role": payload.role, "password_set_directly": bool(payload.password)},
    )
    await session.commit()
    await session.refresh(invitee)
    return invitee


@router.get("", response_model=list[UserOut])
async def list_users(
    user: User = Depends(require_permission("user", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[UserOut]:
    result = await session.execute(select(User).where(User.org_id == user.org_id))
    users = list(result.scalars().all())
    project_ids_by_user = await _project_ids_by_user(session, [u.id for u in users])
    return [
        UserOut(
            id=u.id,
            org_id=u.org_id,
            email=u.email,
            role=u.role,
            is_active=u.is_active,
            invited_at=u.invited_at,
            invite_accepted_at=u.invite_accepted_at,
            project_ids=project_ids_by_user.get(u.id, []),
        )
        for u in users
    ]


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


@router.patch("/{user_id}/role", status_code=204)
async def update_user_role(
    user_id: uuid.UUID,
    payload: UserRoleUpdate,
    user: User = Depends(require_permission("user", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    if payload.role not in BASELINE_ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown role: {payload.role!r}")

    target = await session.get(User, user_id)
    if target is None or target.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    if target.role == "org_admin" and payload.role != "org_admin" and target.is_active:
        if await _other_active_admins_count(session, org_id=user.org_id, excluding=target.id) == 0:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Cannot change the last active org_admin in the organization to another role",
            )

    old_role = target.role
    target.role = payload.role
    await write_audit_log(
        session,
        user=user,
        action="user.role_update",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"target_user_id": str(target.id), "email": target.email, "old_role": old_role, "new_role": payload.role},
    )
    await session.commit()


@router.put("/{user_id}/project-memberships", status_code=204)
async def update_user_project_memberships(
    user_id: uuid.UUID,
    payload: UserProjectMembershipsUpdate,
    user: User = Depends(require_permission("user", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    """Replaces the full set — see UserProjectMembershipsUpdate's own
    docstring for why a PUT rather than incremental add/remove calls."""
    target = await session.get(User, user_id)
    if target is None or target.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    project_ids = set(payload.project_ids)
    if project_ids:
        owned = await session.execute(
            select(Project.id).where(Project.id.in_(project_ids), Project.org_id == user.org_id)
        )
        owned_ids = {row[0] for row in owned}
        unowned = project_ids - owned_ids
        if unowned:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Project(s) not found in this organization: {', '.join(str(pid) for pid in unowned)}",
            )

    await session.execute(delete(ProjectMembership).where(ProjectMembership.user_id == target.id))
    for project_id in project_ids:
        session.add(ProjectMembership(user_id=target.id, project_id=project_id))

    await write_audit_log(
        session,
        user=user,
        action="user.project_memberships_update",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"target_user_id": str(target.id), "email": target.email, "project_ids": [str(pid) for pid in project_ids]},
    )
    await session.commit()


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
        if await _other_active_admins_count(session, org_id=user.org_id, excluding=target.id) == 0:
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
