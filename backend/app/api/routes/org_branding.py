from fastapi import APIRouter, Depends, File, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.org_branding import OrgBranding
from app.models.organization import User
from app.schemas.org_branding import OrgBrandingOut, OrgBrandingUpdate
from app.storage.local_disk import get_object_storage

router = APIRouter(prefix="/org-branding", tags=["org-branding"])


async def _get_or_create(session: AsyncSession, org_id) -> OrgBranding:
    result = await session.execute(select(OrgBranding).where(OrgBranding.org_id == org_id))
    branding = result.scalar_one_or_none()
    if branding is None:
        branding = OrgBranding(org_id=org_id)
        session.add(branding)
        await session.commit()
        await session.refresh(branding)
    return branding


@router.get("", response_model=OrgBrandingOut)
async def get_org_branding(
    user: User = Depends(require_permission("org_branding", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> OrgBranding:
    return await _get_or_create(session, user.org_id)


@router.put("", response_model=OrgBrandingOut)
async def update_org_branding(
    payload: OrgBrandingUpdate,
    user: User = Depends(require_permission("org_branding", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> OrgBranding:
    branding = await _get_or_create(session, user.org_id)
    if payload.company_name is not None:
        branding.company_name = payload.company_name
    if payload.primary_color_hex is not None:
        branding.primary_color_hex = payload.primary_color_hex
    await write_audit_log(
        session,
        user=user,
        action="org_branding.update",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"company_name": branding.company_name, "primary_color_hex": branding.primary_color_hex},
    )
    await session.commit()
    await session.refresh(branding)
    return branding


@router.post("/logo", response_model=OrgBrandingOut)
async def upload_org_branding_logo(
    logo: UploadFile = File(...),
    user: User = Depends(require_permission("org_branding", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> OrgBranding:
    branding = await _get_or_create(session, user.org_id)
    object_key = f"org-branding/{user.org_id}/{logo.filename}"
    await get_object_storage().put(object_key, await logo.read())
    branding.logo_object_key = object_key
    await write_audit_log(
        session,
        user=user,
        action="org_branding.logo_upload",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={"filename": logo.filename},
    )
    await session.commit()
    await session.refresh(branding)
    return branding


@router.delete("/logo", response_model=OrgBrandingOut)
async def delete_org_branding_logo(
    user: User = Depends(require_permission("org_branding", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> OrgBranding:
    branding = await _get_or_create(session, user.org_id)
    branding.logo_object_key = None
    await write_audit_log(
        session,
        user=user,
        action="org_branding.logo_delete",
        resource_type="organization",
        resource_id=user.org_id,
        metadata={},
    )
    await session.commit()
    await session.refresh(branding)
    return branding
