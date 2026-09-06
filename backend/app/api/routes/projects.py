import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_project_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.attack_chain import AttackChain, AttackChainEvidence
from app.models.business_rule import BusinessRule
from app.models.credential import CredentialSet
from app.models.finding import Evidence, Finding
from app.models.finding_ticket import FindingTicket
from app.models.login_macro import LoginMacro
from app.models.organization import User
from app.models.project import AuthorizationRecord, Project, ScopeEntry, Version
from app.models.retest_job import RetestJob
from app.models.review_candidate import ReviewCandidate
from app.models.scan import AgentJob, ScanRun
from app.models.target import Target
from app.models.traffic import TrafficInteraction
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
    include_archived: bool = False,
    user: User = Depends(require_permission("project", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[Project]:
    query = select(Project).where(Project.org_id == user.org_id)
    if not include_archived:
        query = query.where(Project.archived_at.is_(None))
    result = await session.execute(query)
    return list(result.scalars().all())


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(
    project_id: uuid.UUID,
    user: User = Depends(require_permission("project", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> Project:
    return await get_project_or_404(session, project_id, user.org_id)


@router.post("/{project_id}/archive", status_code=204)
async def archive_project(
    project_id: uuid.UUID,
    user: User = Depends(require_permission("project", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    project = await get_project_or_404(session, project_id, user.org_id)
    project.archived_at = datetime.now(timezone.utc)
    await write_audit_log(
        session,
        user=user,
        action="project.archive",
        resource_type="project",
        resource_id=project_id,
        metadata={"name": project.name},
    )
    await session.commit()


@router.post("/{project_id}/unarchive", status_code=204)
async def unarchive_project(
    project_id: uuid.UUID,
    user: User = Depends(require_permission("project", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    project = await get_project_or_404(session, project_id, user.org_id)
    project.archived_at = None
    await write_audit_log(
        session,
        user=user,
        action="project.unarchive",
        resource_type="project",
        resource_id=project_id,
        metadata={"name": project.name},
    )
    await session.commit()


async def _hard_delete_project(session: AsyncSession, project: Project) -> None:
    """No FK in this schema cascades on delete (checked: no ondelete= set
    anywhere in app/models), so a Project's full dependency tree is
    deleted explicitly, deepest-first, inside one transaction."""
    version_ids = select(Version.id).where(Version.project_id == project.id).scalar_subquery()
    scan_run_ids = select(ScanRun.id).where(ScanRun.version_id.in_(version_ids)).scalar_subquery()
    finding_ids = select(Finding.id).where(Finding.scan_run_id.in_(scan_run_ids)).scalar_subquery()
    agent_job_ids = select(AgentJob.id).where(AgentJob.scan_run_id.in_(scan_run_ids)).scalar_subquery()
    attack_chain_ids = (
        select(AttackChain.id).where(AttackChain.scan_run_id.in_(scan_run_ids)).scalar_subquery()
    )
    credential_set_ids = (
        select(CredentialSet.id).where(CredentialSet.version_id.in_(version_ids)).scalar_subquery()
    )

    await session.execute(delete(FindingTicket).where(FindingTicket.finding_id.in_(finding_ids)))
    await session.execute(delete(RetestJob).where(RetestJob.finding_id.in_(finding_ids)))
    await session.execute(delete(Evidence).where(Evidence.finding_id.in_(finding_ids)))
    await session.execute(
        delete(AttackChainEvidence).where(AttackChainEvidence.attack_chain_id.in_(attack_chain_ids))
    )
    await session.execute(delete(AttackChain).where(AttackChain.id.in_(attack_chain_ids)))
    await session.execute(delete(ReviewCandidate).where(ReviewCandidate.scan_run_id.in_(scan_run_ids)))
    await session.execute(delete(Finding).where(Finding.scan_run_id.in_(scan_run_ids)))
    await session.execute(delete(AgentJob).where(AgentJob.id.in_(agent_job_ids)))
    await session.execute(delete(ScanRun).where(ScanRun.id.in_(scan_run_ids)))
    await session.execute(delete(LoginMacro).where(LoginMacro.version_id.in_(version_ids)))
    await session.execute(
        delete(TrafficInteraction).where(TrafficInteraction.version_id.in_(version_ids))
    )
    await session.execute(delete(BusinessRule).where(BusinessRule.version_id.in_(version_ids)))
    await session.execute(delete(Target).where(Target.version_id.in_(version_ids)))
    await session.execute(delete(CredentialSet).where(CredentialSet.id.in_(credential_set_ids)))
    await session.execute(delete(ScopeEntry).where(ScopeEntry.version_id.in_(version_ids)))
    await session.execute(
        delete(AuthorizationRecord).where(AuthorizationRecord.version_id.in_(version_ids))
    )
    await session.execute(delete(Version).where(Version.project_id == project.id))
    await session.delete(project)


@router.delete("/{project_id}", status_code=204)
async def delete_project(
    project_id: uuid.UUID,
    user: User = Depends(require_permission("project", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    """Permanent hard delete (§6, admin-only via RBAC — 'delete' isn't
    granted to project_lead/analyst/viewer in the baseline matrix). The
    UI is expected to gate this behind a typed-confirmation dialog; the
    API's own guardrail is the permission check itself.
    """
    project = await get_project_or_404(session, project_id, user.org_id)
    await write_audit_log(
        session,
        user=user,
        action="project.delete",
        resource_type="project",
        resource_id=project_id,
        metadata={"name": project.name},
    )
    await _hard_delete_project(session, project)
    await session.commit()
