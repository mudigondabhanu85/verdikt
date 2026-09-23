from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.auth.security import create_access_token, hash_password, verify_password
from app.db.session import get_db_session
from app.models.organization import Organization, User
from app.schemas.auth import ChangePasswordRequest, LoginRequest, TokenResponse, UserOut, UserRegister

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: UserRegister, session: AsyncSession = Depends(get_db_session)) -> TokenResponse:
    """Bootstraps a new Organization with its first user as org_admin.
    Subsequent users are provisioned by that org_admin (out of scope for
    Phase 0's CRUD surface — a Phase-0 org has exactly its founding user)."""
    existing = await session.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email already registered")

    org = Organization(name=payload.org_name)
    session.add(org)
    await session.flush()

    user = User(
        org_id=org.id,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role="org_admin",
    )
    session.add(user)
    await session.commit()

    return TokenResponse(access_token=create_access_token(user.id))


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, session: AsyncSession = Depends(get_db_session)) -> TokenResponse:
    result = await session.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if (
        user is None
        or not user.is_active
        or user.hashed_password is None  # SSO-only user (§9) — no password to check
        or not verify_password(payload.password, user.hashed_password)
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    return TokenResponse(access_token=create_access_token(user.id))


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)) -> User:
    return user


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    payload: ChangePasswordRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    # SSO-only users (§9) have no password on file to check against — the
    # thing this endpoint exists to change doesn't exist for them.
    if user.hashed_password is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "This account signs in via SSO and has no password to change.",
        )
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")
    user.hashed_password = hash_password(payload.new_password)
    await session.commit()
