import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_project_or_404
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.organization import User
from app.models.project import Project
from app.schemas.project import ProjectCreate, ProjectOut

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectOut, status_code=201)
async def create_project(
    payload: ProjectCreate,
    user: User = Depends(require_permission("project", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> Project:
    project = Project(org_id=user.org_id, name=payload.name, created_by=user.id)
    session.add(project)
    await session.commit()
    await session.refresh(project)
    return project


@router.get("", response_model=list[ProjectOut])
async def list_projects(
    user: User = Depends(require_permission("project", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[Project]:
    result = await session.execute(select(Project).where(Project.org_id == user.org_id))
    return list(result.scalars().all())


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(
    project_id: uuid.UUID,
    user: User = Depends(require_permission("project", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> Project:
    return await get_project_or_404(session, project_id, user.org_id)
