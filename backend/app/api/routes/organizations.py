from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.organization import Organization, User
from app.schemas.organization import OrganizationOut

router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.get("/me", response_model=OrganizationOut)
async def get_my_organization(
    user: User = Depends(require_permission("organization", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> Organization:
    return await session.get(Organization, user.org_id)
